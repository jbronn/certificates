package acme

import (
	"crypto/x509"
	"encoding/json"
	"reflect"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/randutil"
	"github.com/smallstep/nosql"
)

var defaultOrderExpiry = time.Hour * 24

// Order contains order metadata for the ACME protocol order type.
type Order struct {
	ID             string       `json:"id"`
	AccountID      string       `json:"accountID"`
	Created        time.Time    `json:"created"`
	Status         string       `json:"status"`
	Expires        time.Time    `json:"expires,omitempty"`
	Identifiers    []Identifier `json:"identifiers"`
	NotBefore      time.Time    `json:"notBefore,omitempty"`
	NotAfter       time.Time    `json:"notAfter,omitempty"`
	Error          interface{}  `json:"error,omitempty"`
	Authorizations []string     `json:"authorizations"`
	Certificate    string       `json:"certificate,omitempty"`
}

// OrderOptions options with which to create a new Order.
type OrderOptions struct {
	AccountID   string       `json:"accID"`
	Identifiers []Identifier `json:"identifiers"`
	NotBefore   time.Time    `json:"notBefore"`
	NotAfter    time.Time    `json:"notAfter"`
}

// NewOrder returns a new Order type.
func NewOrder(db nosql.DB, ops OrderOptions) (*Order, error) {
	id, err := randutil.ASCII(idLen)
	if err != nil {
		return nil, errors.Wrap(err, "error generating random id for ACME challenge")
	}

	authzs := make([]string, len(ops.Identifiers))
	for i, identifier := range ops.Identifiers {
		authz, err := NewAuthz(db, ops.AccountID, identifier)
		if err != nil {
			return nil, err
		}
		authzs[i] = authz.GetID()
	}

	now := time.Now().UTC()
	o := &Order{
		ID:             id,
		AccountID:      ops.AccountID,
		Created:        now,
		Status:         statusPending,
		Expires:        now.Add(defaultOrderExpiry),
		Identifiers:    ops.Identifiers,
		NotBefore:      ops.NotBefore,
		NotAfter:       ops.NotAfter,
		Authorizations: authzs,
	}
	if err := o.save(db, nil); err != nil {
		return nil, err
	}

	// TODO should we delete the Order if there are errors downstream?

	// Update the "order IDs by account ID" index //
	orderIDs, err := GetOrderIDsByAccount(db, ops.AccountID)
	if err != nil {
		return nil, err
	}
	newOrderIDs := append(orderIDs, o.ID)
	oldb, err := json.Marshal(orderIDs)
	if err != nil {
		return nil, errors.Wrap(err, "error marshaling old order IDs slice")
	}
	newb, err := json.Marshal(newOrderIDs)
	if err != nil {
		return nil, errors.Wrap(err, "error marshaling new order IDs slice")
	}
	_, swapped, err := db.CmpAndSwap(ordersByAccountIDTable, []byte(o.AccountID), oldb, newb)
	switch {
	case err != nil:
		return nil, errors.Wrapf(err, "error storing order IDs for account %s", o.AccountID)
	case !swapped:
		return nil, errors.Wrapf(err, "error storing order IDs for account %s; order IDs changed since last read", o.AccountID)
	default:
		return o, nil
	}
}

func (o *Order) save(db nosql.DB, old *Order) error {
	var (
		err  error
		oldB []byte
	)
	if old == nil {
		oldB = nil
	} else {
		if oldB, err = json.Marshal(old); err != nil {
			return errors.Wrap(err, "error marshaling old acme order")
		}
	}

	newB, err := json.Marshal(o)
	if err != nil {
		return errors.Wrap(err, "error marshaling new acme order")
	}

	_, swapped, err := db.CmpAndSwap(orderTable, []byte(o.ID), oldB, newB)
	switch {
	case err != nil:
		return errors.Wrap(err, "error writing acme order to disk")
	case !swapped:
		return errors.Errorf("error writing acme order to disk; order %s has changed since last read", o.ID)
	default:
		return nil
	}
}

// UpdateStatus updates Order status if necessary.
func (o *Order) UpdateStatus(db nosql.DB) (*Order, error) {
	_newOrder := *o
	newOrder := &_newOrder

	now := time.Now().UTC()
	switch o.Status {
	case statusInvalid:
		return o, nil
	case statusValid:
		return o, nil
	case statusReady:
		// check expiry
		if now.After(o.Expires) {
			newOrder.Status = statusInvalid
			// TODO add something to error/problem indicating expiration.
			break
		}
		return o, nil
	case statusPending:
		// check expiry
		if now.After(o.Expires) {
			newOrder.Status = statusInvalid
			// TODO add something to error/problem indicating expiration.
			break
		}

		var allValid = true
		for _, azID := range o.Authorizations {
			authz, err := GetAuthz(db, azID)
			if err != nil {
				return o, err
			}
			if authz, err = authz.UpdateStatus(db); err != nil {
				return o, err
			}
			if authz.GetStatus() != statusValid {
				allValid = false
				break
			}
		}

		if allValid {
			newOrder.Status = statusValid
			break
		}
		// Still pending, so do nothing.
		return o, nil
	}

	if err := newOrder.save(db, o); err != nil {
		return o, err
	}
	return newOrder, nil
}

// Finalize signs a certificate if the necessary conditions for Order completion
// have been met.
func (o *Order) Finalize(db nosql.DB, csr x509.CertificateRequest) (*Order, error) {
	var err error
	if o, err = o.UpdateStatus(db); err != nil {
		return o, err
	}
	switch o.Status {
	case statusInvalid:
		return o, errors.Errorf("order %s has been abandoned", o.ID)
	case statusValid:
		return o, errors.Errorf("order %s is already valid", o.ID)
	case statusPending:
		return o, errors.Errorf("order %s is not ready", o.ID)
	case statusReady:
		break
	default:
		return o, errors.Errorf("unexpected status %s for order %s", o.Status, o.ID)
	}

	// Validate identifier names against CSR alternative names //
	var csrNames map[string]int
	if csr.Subject.CommonName != "" {
		csrNames[csr.Subject.CommonName] = 1
	}
	for _, n := range csr.DNSNames {
		csrNames[n] = 1
	}

	var orderNames map[string]int
	for _, n := range o.Identifiers {
		orderNames[n.Value] = 1
	}

	if !reflect.DeepEqual(csrNames, orderNames) {
		// TODO Note reason on the Order error object.
		return o, errors.Errorf("CSR names do not match order identifiers exactly")
	}

	// Create a new certificate
	// TODO
	_newOrder := *o
	newOrder := &_newOrder
	newOrder.Certificate = "boogers"
	if err := newOrder.save(db, o); err != nil {
		return o, err
	}
	return newOrder, nil
}

// GetOrder retrieves and unmarshals an ACME Order type from the database.
func GetOrder(db nosql.DB, id string) (*Order, error) {
	b, err := db.Get(orderTable, []byte(id))
	if err != nil {
		// TODO return a proper API error indicating bad request.
		return nil, errors.WithStack(err)
	}
	var o Order
	if err := json.Unmarshal(b, &o); err != nil {
		return nil, err
	}
	return &o, nil
}

// GetOrderIDsByAccount retrieves a list of Order IDs that were created by the
// account.
func GetOrderIDsByAccount(db nosql.DB, id string) ([]string, error) {
	b, err := db.Get(ordersByAccountIDTable, []byte(id))
	if err != nil {
		// TODO return a proper API error indicating bad request.
		return nil, errors.WithStack(err)
	}
	var orderIDs []string
	if err := json.Unmarshal(b, &orderIDs); err != nil {
		return nil, err
	}
	return orderIDs, nil
}

type acmeOrder struct {
	Status         string       `json:"status"`
	Expires        string       `json:"expires,omitempty"`
	Identifiers    []Identifier `json:"identifiers"`
	NotBefore      string       `json:"notBefore,omitempty"`
	NotAfter       string       `json:"notAfter,omitempty"`
	Error          interface{}  `json:"error,omitempty"`
	Authorizations []string     `json:"authorizations"`
	Finalize       string       `json:"finalize"`
	Certificate    string       `json:"certificate,omitempty"`
}

// ToACME converts the internal Order type into the public acmeOrder type for
// presentation in the ACME protocol.
func (o *Order) ToACME(db nosql.DB, dir *Directory) (interface{}, error) {
	azs := make([]string, len(o.Authorizations))
	for i, aid := range o.Authorizations {
		azs[i] = dir.GetAuthz(aid, true)
	}
	ao := &acmeOrder{
		Status:         o.Status,
		Expires:        o.Expires.Format(time.RFC3339),
		Identifiers:    o.Identifiers,
		NotBefore:      o.NotBefore.Format(time.RFC3339),
		NotAfter:       o.NotAfter.Format(time.RFC3339),
		Authorizations: azs,
		Finalize:       dir.GetFinalize(o.ID, true),
	}

	if o.Certificate != "" {
		ao.Certificate = dir.GetCertificate(o.Certificate, true)
	}
	return ao, nil
}
