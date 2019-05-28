package acme

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/jose"
	"github.com/smallstep/nosql"
)

// Challenge is the interface ACME challenege types must implement.
type Challenge interface {
	save(db nosql.DB, swap Challenge) error
	updateAuthz(db nosql.DB) error
	Validate(nosql.DB, *jose.JSONWebKey) (Challenge, bool, error)
	GetType() string
	GetStatus() string
	GetID() string
	GetAuthzID() string
	GetToken() string
	GetAccountID() string
	ToACME(nosql.DB, *Directory) (interface{}, error)
}

// ChallengeOptions is the type used to created a new Challenge.
type ChallengeOptions struct {
	AccountID  string
	AuthzID    string
	Identifier Identifier
}

// BaseChallenge is the base Challenge type that others build from.
type BaseChallenge struct {
	ID         string    `json:"id"`
	AccountID  string    `json:"accountID"`
	AuthzID    string    `json:"authzID"`
	Type       string    `json:"type"`
	Status     string    `json:"status"`
	Token      string    `json:"token"`
	Validated  time.Time `json:"validated"`
	Identifier string    `json:"identifier"`
	Created    time.Time
}

func newBaseChallenge(accountID, authzID string) (*BaseChallenge, error) {
	id, err := randID()
	if err != nil {
		return nil, errors.Wrap(err, "error generating random id for ACME challenge")
	}
	token, err := randID()
	if err != nil {
		return nil, errors.Wrap(err, "error generating token for ACME challenge")
	}

	return &BaseChallenge{
		ID:        id,
		AccountID: accountID,
		AuthzID:   authzID,
		Status:    statusPending,
		Token:     token,
		Created:   time.Now().UTC(),
	}, nil
}

// GetID returns the id of the BaseChallenge.
func (bc *BaseChallenge) GetID() string {
	return bc.ID
}

// GetAuthzID returns the Authz ID of the BaseChallenge.
func (bc *BaseChallenge) GetAuthzID() string {
	return bc.AuthzID
}

// GetAccountID returns the account id of the BaseChallenge.
func (bc *BaseChallenge) GetAccountID() string {
	return bc.AccountID
}

// GetType returns the type of the BaseChallenge.
func (bc *BaseChallenge) GetType() string {
	return bc.Type
}

// GetStatus returns the status of the BaseChallenge.
func (bc *BaseChallenge) GetStatus() string {
	return bc.Status
}

// GetToken returns the token of the BaseChallenge.
func (bc *BaseChallenge) GetToken() string {
	return bc.Token
}

// GetValidated returns the token of the BaseChallenge.
func (bc *BaseChallenge) GetValidated() time.Time {
	return bc.Validated
}

// ToACME converts the internal Challenge type into the public acmeChallenge
// type for presentation in the ACME protocol.
func (bc *BaseChallenge) ToACME(db nosql.DB, dir *Directory) (interface{}, error) {
	ac := &acmeChallenge{
		Type:   bc.GetType(),
		Status: bc.GetStatus(),
		Token:  bc.GetToken(),
		URL:    dir.GetChallenge(bc.GetID(), true),
	}
	if !bc.Validated.IsZero() {
		ac.Validated = bc.Validated.Format(time.RFC3339)
	}
	return ac, nil
}

// save writes the challenge to disk. For new challenges 'old' should be nil,
// otherwise 'old' should be a pointer to the acme challenge as it was at the
// start of the request. This method will fail if the value currently found
// in the bucket/row does not match the value of 'old'.
func (bc *BaseChallenge) save(db nosql.DB, old Challenge) error {
	newB, err := json.Marshal(bc)
	if err != nil {
		return errors.Wrap(err, "error marshaling new acme challenge")
	}
	var oldB []byte
	if old == nil {
		oldB = nil
	} else {
		oldB, err = json.Marshal(old)
		if err != nil {
			return errors.Wrap(err, "error marshaling old acme challenge")
		}
	}

	_, swapped, err := db.CmpAndSwap(challengeTable, []byte(bc.ID), oldB, newB)
	switch {
	case err != nil:
		return errors.Wrap(err, "error saving acme challenge")
	case !swapped:
		return errors.New("acme challenge has changed since last read")
	default:
		return nil
	}
}

func (bc *BaseChallenge) clone() *BaseChallenge {
	u := *bc
	return &u
}

// updateAuthz updates the parent Authz of the challenge.
func (bc *BaseChallenge) updateAuthz(db nosql.DB) error {
	authz, err := GetAuthz(db, bc.AuthzID)
	if err != nil {
		return err
	}
	if _, err := authz.UpdateStatus(db); err != nil {
		return err
	}
	return nil
}

// unmarshalChallenge unmarshals a challenge type into the correct sub-type.
func unmarshalChallenge(data []byte) (Challenge, error) {
	var getType struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &getType); err != nil {
		return nil, errors.Wrap(err, "error unmarshaling authz type")
	}

	switch getType.Type {
	case "dns-01":
		var ch DNS01Challenge
		if err := json.Unmarshal(data, &ch); err != nil {
			return nil, errors.Wrap(err, "error unmarshaling challenge type into DNS01Challenge")
		}
		return &ch, nil
	case "http-01":
		var ch HTTP01Challenge
		if err := json.Unmarshal(data, &ch); err != nil {
			return nil, errors.Wrap(err, "error unmarshaling challenge type into HTTP01Challenge")
		}
		return &ch, nil
	default:
		return nil, errors.Errorf("unexpected challenge type %s", getType.Type)
	}
}

// HTTP01Challenge represents an http-01 acme challenge.
type HTTP01Challenge struct {
	*BaseChallenge
}

// NewHTTP01Challenge returns a new acme http-01 challenge.
func NewHTTP01Challenge(db nosql.DB, ops ChallengeOptions) (Challenge, error) {
	bc, err := newBaseChallenge(ops.AccountID, ops.AuthzID)
	if err != nil {
		return nil, err
	}
	bc.Type = "http-01"
	bc.Identifier = ops.Identifier.Value

	hc := &HTTP01Challenge{bc}
	if err := hc.save(db, nil); err != nil {
		return nil, err
	}
	return hc, nil
}

// Validate attempts to validate the challenge. If the challenge has been
// satisfactorily validated, the 'status' and 'validated' attributes are
// updated.
func (hc *HTTP01Challenge) Validate(db nosql.DB, jwk *jose.JSONWebKey) (Challenge, bool, error) {
	// If already valid or invalid then return without performing validation.
	if hc.GetStatus() == statusValid {
		return hc, true, nil
	} else if hc.GetStatus() == statusInvalid {
		return hc, false, nil
	}
	url := fmt.Sprintf("http://%s/.well-known/acme-challenge/%s", hc.Identifier, hc.Token)

	resp, err := http.Get(url)
	if err != nil {
		// TODO store the error cause on the challenge.
		return nil, false, errors.Wrapf(err, "error doing http GET for url %s", url)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, false, errors.Wrapf(err, "error reading response body for url %s", url)
	}
	keyAuth := strings.Trim(string(body), "\r\n")

	expected, err := keyAuthorization(hc.Token, jwk)
	if err != nil {
		// TODO better error
		return hc, false, err
	}
	if keyAuth != expected {
		// TODO store the error cause on the challenge.
		return nil, false, errors.Errorf("keyAuthorization does not match; expected %s, but got %s", expected, keyAuth)
	}

	// Update and store the challenge.
	upd := &HTTP01Challenge{hc.BaseChallenge.clone()}
	if err := upd.save(db, hc); err != nil {
		return nil, false, err
	}
	return upd, true, nil
}

// DNS01Challenge represents an dns-01 acme challenge.
type DNS01Challenge struct {
	*BaseChallenge
}

// NewDNS01Challenge returns a new acme dns-01 challenge.
func NewDNS01Challenge(db nosql.DB, ops ChallengeOptions) (Challenge, error) {
	bc, err := newBaseChallenge(ops.AccountID, ops.AuthzID)
	if err != nil {
		return nil, err
	}
	bc.Type = "dns-01"
	bc.Identifier = ops.Identifier.Value

	dc := &HTTP01Challenge{bc}
	if err := dc.save(db, nil); err != nil {
		return nil, err
	}
	return dc, nil
}

func keyAuthorization(token string, jwk *jose.JSONWebKey) (string, error) {
	thumbprint, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", errors.Wrap(err, "error generating JWK thumbprint")
	}
	encPrint := base64.RawURLEncoding.EncodeToString(thumbprint)
	return fmt.Sprintf("%s.%s", token, encPrint), nil
}

// Validate attempts to validate the challenge. If the challenge has been
// satisfactorily validated, the 'status' and 'validated' attributes are
// updated.
func (dc *DNS01Challenge) Validate(db nosql.DB, jwk *jose.JSONWebKey) (Challenge, bool, error) {
	// If already valid or invalid then return without performing validation.
	if dc.GetStatus() == statusValid {
		return dc, true, nil
	} else if dc.GetStatus() == statusInvalid {
		return dc, false, nil
	}

	expectedKeyAuth, err := keyAuthorization(dc.Token, jwk)
	if err != nil {
		return nil, false, err
	}
	txtRecords, err := net.LookupTXT(dc.Identifier)
	if err != nil {
		// TODO store the error cause on the challenge.
		return nil, false, errors.Wrapf(err, "error looking up TXT records for domain %s", dc.Identifier)
	}

	var found bool
	for _, r := range txtRecords {
		if r == expectedKeyAuth {
			found = true
			break
		}
	}

	if !found {
		return nil, false, nil
	}

	// Update and store the challenge.
	upd := &DNS01Challenge{dc.BaseChallenge.clone()}
	upd.Status = statusValid
	upd.Validated = time.Now().UTC()

	if err := upd.save(db, dc); err != nil {
		return nil, false, err
	}
	return upd, true, nil
}

// GetChallenge retrieves and unmarshals an ACME challenge type from the database.
func GetChallenge(db nosql.DB, id string) (Challenge, error) {
	b, err := db.Get(challengeTable, []byte(id))
	if err != nil {
		// TODO return a proper API error indicating bad request.
		return nil, errors.WithStack(err)
	}
	ch, err := unmarshalChallenge(b)
	if err != nil {
		return nil, err
	}
	return ch, nil
}

// acmeChallenge is a subset of the Challenge type containing only those attributes
// required for responses in the ACME protocol.
type acmeChallenge struct {
	Type      string `json:"type"`
	Status    string `json:"status"`
	Token     string `json:"token"`
	Validated string `json:"validated,omitempty"`
	URL       string `json:"url"`
}
