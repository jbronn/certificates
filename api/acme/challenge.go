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
	"github.com/smallstep/cli/crypto/randutil"
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
	GetAccountID() string
	ToACME(nosql.DB, *Directory) (*acmeChallenge, error)
}

// ChallengeOptions is the type used to created a new Challenge.
type ChallengeOptions struct {
	AccountID  string
	AuthzID    string
	Identifier Identifier
}

type baseChallenge struct {
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

func newBaseChallenge(accountID, authzID string) (*baseChallenge, error) {
	id, err := randutil.ASCII(idLen)
	if err != nil {
		return nil, errors.Wrap(err, "error generating random id for ACME challenge")
	}
	token, err := randutil.ASCII(tokLen)
	if err != nil {
		return nil, errors.Wrap(err, "error generating token for ACME challenge")
	}

	return &baseChallenge{
		ID:        id,
		AccountID: accountID,
		AuthzID:   authzID,
		Status:    statusPending,
		Token:     token,
		Created:   time.Now().UTC(),
	}, nil
}

// GetID returns the id of the baseChallenge.
func (bc *baseChallenge) GetID() string {
	return bc.ID
}

// GetAccountID returns the account id of the baseChallenge.
func (bc *baseChallenge) GetAccountID() string {
	return bc.AccountID
}

// GetType returns the type of the baseChallenge.
func (bc *baseChallenge) GetType() string {
	return bc.Type
}

// GetStatus returns the status of the baseChallenge.
func (bc *baseChallenge) GetStatus() string {
	return bc.Status
}

// GetToken returns the token of the baseChallenge.
func (bc *baseChallenge) GetToken() string {
	return bc.Token
}

// GetValidated returns the token of the baseChallenge.
func (bc *baseChallenge) GetValidated() time.Time {
	return bc.Validated
}

// ToACME converts the internal Challenge type into the public acmeChallenge
// type for presentation in the ACME protocol.
func (bc *baseChallenge) ToACME(db nosql.DB, dir *Directory) (*acmeChallenge, error) {
	ac := &acmeChallenge{
		Type:   bc.GetType(),
		Status: bc.GetStatus(),
		Token:  bc.GetStatus(),
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
func (bc *baseChallenge) save(db nosql.DB, old Challenge) error {
	newB, err := json.Marshal(bc)
	if err != nil {
		return errors.Wrap(err, "error marshaling new acme challenge")
	}
	var oldB []byte
	if old == nil {
		oldB = nil
	} else {
		oldB, err = json.Marshal(bc)
		if err != nil {
			return errors.Wrap(err, "error marshaling old acme challenge")
		}
	}

	_, swapped, err := db.CmpAndSwap(challengeTable, []byte(bc.ID), oldB, newB)
	switch {
	case err != nil:
		return errors.Wrap(err, "error saving acme challenge")
	case !swapped:
		return errors.Wrap(err, "acme challenge has changed since last read")
	default:
		return nil
	}
}

// updateAuthz updates the parent Authz of the challenge.
func (bc *baseChallenge) updateAuthz(db nosql.DB) error {
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
		Type string `json:"identifier"`
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
	*baseChallenge
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
	auth := string(body)

	prefix := hc.Token + "."
	if !strings.HasPrefix(auth, prefix) {
		// TODO store problem cause on the challenge
		return nil, false, nil
	}
	keyAuth := strings.TrimPrefix(auth, prefix)

	thumbprint, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, false, errors.Wrap(err, "error generating JWK thumbprint")
	}
	if keyAuth != base64.RawURLEncoding.EncodeToString(thumbprint) {
		// TODO store the error cause on the challenge.
		return nil, false, errors.New("keyAuthorization does not match")
	}

	// Update and store the challenge.
	_upd := *hc
	upd := &_upd
	upd.Status = statusValid
	upd.Validated = time.Now().UTC()

	if err := upd.save(db, hc); err != nil {
		return nil, false, err
	}
	// Update the status on the Authz.
	if err := upd.updateAuthz(db); err != nil {
		return nil, false, err
	}
	return upd, true, nil
}

// DNS01Challenge represents an dns-01 acme challenge.
type DNS01Challenge struct {
	*baseChallenge
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
	_upd := *dc
	upd := &_upd
	upd.Status = statusValid
	upd.Validated = time.Now().UTC()

	if err := upd.save(db, dc); err != nil {
		return nil, false, err
	}
	// Update the status on the Authz.
	if err := upd.updateAuthz(db); err != nil {
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
}
