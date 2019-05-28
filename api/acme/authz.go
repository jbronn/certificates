package acme

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/nosql"
)

var defaultExpiryDuration = time.Hour * 24

// Authz is the interface that the various authz types must implement.
type Authz interface {
	save(nosql.DB, Authz) error
	GetID() string
	GetAccountID() string
	GetType() string
	GetStatus() string
	GetExpiry() time.Time
	IsWildcard() bool
	UpdateStatus(db nosql.DB) (Authz, error)
	ToACME(nosql.DB, *Directory) (interface{}, error)
}

// BaseAuthz is the base authz type that others build from.
type BaseAuthz struct {
	ID         string     `json:"id"`
	AccountID  string     `json:"accountID"`
	Identifier Identifier `json:"identifier"`
	Status     string     `json:"status"`
	Expires    time.Time  `json:"expires"`
	Challenges []string   `json:"challenges"`
	Wildcard   bool       `json:"wildcard"`
	Created    time.Time
}

func newBaseAuthz(accID string, identifier Identifier) (*BaseAuthz, error) {
	id, err := randID()
	if err != nil {
		return nil, errors.Wrap(err, "error generating random id for ACME challenge")
	}

	ba := &BaseAuthz{
		ID:         id,
		AccountID:  accID,
		Status:     statusPending,
		Created:    time.Now().UTC(),
		Expires:    time.Now().UTC().Add(defaultExpiryDuration),
		Identifier: identifier,
	}

	if strings.HasPrefix(identifier.Value, "*.") {
		ba.Wildcard = true
		ba.Identifier = Identifier{
			Value: strings.TrimPrefix(identifier.Value, "*."),
			Type:  identifier.Type,
		}
	}

	return ba, nil
}

// GetID returns the ID of the authz.
func (ba *BaseAuthz) GetID() string {
	return ba.ID
}

// GetAccountID returns the Account ID that created the authz.
func (ba *BaseAuthz) GetAccountID() string {
	return ba.AccountID
}

// GetType returns the type of the authz.
func (ba *BaseAuthz) GetType() string {
	return ba.Identifier.Type
}

// GetIdentifier returns the identifier for the authz.
func (ba *BaseAuthz) GetIdentifier() Identifier {
	return ba.Identifier
}

// GetStatus returns the status of the authz.
func (ba *BaseAuthz) GetStatus() string {
	return ba.Status
}

// IsWildcard returns true if the authz identifier has a '*', false otherwise.
func (ba *BaseAuthz) IsWildcard() bool {
	return ba.Wildcard
}

// GetExpiry returns the expiration time of the authz.
func (ba *BaseAuthz) GetExpiry() time.Time {
	return ba.Expires
}

// ToACME converts the internal Authz type into the public acmeAuthz type for
// presentation in the ACME protocol.
func (ba *BaseAuthz) ToACME(db nosql.DB, dir *Directory) (interface{}, error) {
	var chs = make([]interface{}, len(ba.Challenges))
	for i, chID := range ba.Challenges {
		ch, err := GetChallenge(db, chID)
		if err != nil {
			return nil, err
		}
		chs[i], err = ch.ToACME(db, dir)
		if err != nil {
			return nil, err
		}
	}
	return &acmeAuthz{
		Identifier: ba.Identifier,
		Status:     ba.GetStatus(),
		Challenges: chs,
		Wildcard:   ba.IsWildcard(),
		Expires:    ba.Expires.Format(time.RFC3339),
	}, nil
}

func (ba *BaseAuthz) save(db nosql.DB, old Authz) error {
	var (
		err        error
		oldB, newB []byte
	)
	if old == nil {
		oldB = nil
	} else {
		if oldB, err = json.Marshal(old); err != nil {
			return errors.Wrap(err, "error marshaling Authz")
		}
	}
	if newB, err = json.Marshal(ba); err != nil {
		return errors.Wrap(err, "error marshaling Authz")
	}
	_, swapped, err := db.CmpAndSwap(authzTable, []byte(ba.ID), oldB, newB)
	switch {
	case err != nil:
		return errors.Wrapf(err, "error storing authz with ID %s", ba.ID)
	case !swapped:
		return errors.Errorf("error storing authz with ID %s; value has changed since last read", ba.ID)
	default:
		return nil
	}
}

// UpdateStatus attempts to update the status on a BaseAuthz and stores the
// updating object if necessary.
func (ba *BaseAuthz) UpdateStatus(db nosql.DB) (Authz, error) {
	_newAuthz := *ba
	newAuthz := &_newAuthz

	now := time.Now().UTC()
	switch ba.Status {
	case statusInvalid:
		return ba, nil
	case statusValid:
		return ba, nil
	case statusReady:
		// check expiry
		if now.After(ba.Expires) {
			newAuthz.Status = statusInvalid
			// TODO add something to error/problem indicating expiration.
			break
		}
		return ba, nil
	case statusPending:
		// check expiry
		if now.After(ba.Expires) {
			newAuthz.Status = statusInvalid
			// TODO add something to error/problem indicating expiration.
			break
		}

		var isValid = true
		for _, chID := range ba.Challenges {
			ch, err := GetChallenge(db, chID)
			if err != nil {
				return ba, err
			}
			if ch.GetStatus() == statusValid {
				isValid = true
				break
			}
		}

		if isValid {
			newAuthz.Status = statusValid
			break
		}
		// Still pending, so do nothing.
		return ba, nil
	}

	if err := newAuthz.save(db, ba); err != nil {
		return ba, err
	}
	return newAuthz, nil
}

// unmarshalAuthz unmarshals an authz type into the correct sub-type.
func unmarshalAuthz(data []byte) (Authz, error) {
	var getType struct {
		Identifier Identifier `json:"identifier"`
	}
	if err := json.Unmarshal(data, &getType); err != nil {
		return nil, errors.Wrap(err, "error unmarshaling authz type")
	}

	switch getType.Identifier.Type {
	case "dns":
		var az DNSAuthz
		if err := json.Unmarshal(data, &az); err != nil {
			return nil, errors.Wrap(err, "error unmarshaling authz type into DNSAuthz")
		}
		return &az, nil
	default:
		return nil, errors.Errorf("unexpected authz type %s", getType.Identifier.Type)
	}
}

// DNSAuthz represents a dns acme authorization.
type DNSAuthz struct {
	*BaseAuthz
}

// NewAuthz returns a new acme authorization object based on the identifier
// type.
func NewAuthz(db nosql.DB, accID string, identifier Identifier) (a Authz, err error) {
	switch identifier.Type {
	case "dns":
		a, err = newDNSAuthz(db, accID, identifier)
	default:
		err = errors.Errorf("unexpected authorization type %s", identifier.Type)
	}
	return
}

// newDNSAuthz returns a new dns acme authorization object.
func newDNSAuthz(db nosql.DB, accID string, identifier Identifier) (Authz, error) {
	ba, err := newBaseAuthz(accID, identifier)
	if err != nil {
		return nil, err
	}

	ch1, err := NewHTTP01Challenge(db, ChallengeOptions{
		AccountID:  accID,
		AuthzID:    ba.ID,
		Identifier: identifier})
	if err != nil {
		return nil, err
	}
	ch2, err := NewDNS01Challenge(db, ChallengeOptions{
		AccountID:  accID,
		AuthzID:    ba.ID,
		Identifier: identifier})
	if err != nil {
		return nil, err
	}
	ba.Challenges = []string{ch1.GetID(), ch2.GetID()}

	da := &DNSAuthz{ba}
	if err := da.save(db, nil); err != nil {
		return nil, err
	}

	return da, nil
}

// GetAuthz retrieves and unmarshals an ACME authz type from the database.
func GetAuthz(db nosql.DB, id string) (Authz, error) {
	b, err := db.Get(authzTable, []byte(id))
	if err != nil {
		// TODO return a proper API error indicating bad request.
		return nil, errors.WithStack(err)
	}
	az, err := unmarshalAuthz(b)
	if err != nil {
		return nil, err
	}
	return az, nil
}

// acmeAuthz is a subset of the Authz type containing only those attributes
// required for responses in the ACME protocol.
type acmeAuthz struct {
	Identifier Identifier    `json:"identifier"`
	Status     string        `json:"status"`
	Expires    string        `json:"expires"`
	Challenges []interface{} `json:"challenges"`
	Wildcard   bool          `json:"wildcard"`
}
