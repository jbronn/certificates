package acme

import (
	"crypto/x509"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/cli/crypto/randutil"
)

// Authority is the interface implemented by a CA authority.
type Authority interface {
	Sign(cr *x509.CertificateRequest, opts provisioner.Options, signOpts ...provisioner.SignOption) (*x509.Certificate, *x509.Certificate, error)
}

// Identifier encodes the type that an order pertains to.
type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

var (
	accountTable           = []byte("acme-accounts")
	accountByKeyIDTable    = []byte("acme-keyID-accountID-index")
	authzTable             = []byte("acme-authzs")
	challengeTable         = []byte("acme-challenges")
	nonceTable             = []byte("nonce-table")
	orderTable             = []byte("acme-orders")
	ordersByAccountIDTable = []byte("acme-account-orders-index")
)

var (
	statusValid       = "valid"
	statusInvalid     = "invalid"
	statusRevoked     = "revoked"
	statusExpired     = "expired"
	statusPending     = "pending"
	statusProcessing  = "processing"
	statusDeactivated = "deactivated"
	statusActive      = "active"
	statusReady       = "ready"
)

var (
	idLen  = 32
	tokLen = 32
)

func randID() (val string, err error) {
	val, err = randutil.Alphanumeric(idLen)
	return val, errors.Wrap(err, "error generating random alphanumeric ID")
}
