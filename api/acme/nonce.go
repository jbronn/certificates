package acme

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/nosql"
	"github.com/smallstep/nosql/database"
)

var nonceLen = 32

// Nonce contains nonce metadata used in the ACME protocol.
type Nonce struct {
	Created time.Time
}

// NewNonce creates, stores, and returns an ACME replay-nonce.
func NewNonce(db nosql.DB) (string, error) {
	b := make([]byte, nonceLen)
	_, err := rand.Read(b)
	if err != nil {
		return "", errors.Wrap(err, "error reading random bytes from crypto/rand")
	}

	val := base64.RawURLEncoding.EncodeToString(b)
	n := &Nonce{
		Created: time.Now().UTC(),
	}
	nb, err := json.Marshal(n)
	if err != nil {
		return "", errors.Wrap(err, "error marshaling nonce")
	}
	if err := db.Set(nonceTable, []byte(val), nb); err != nil {
		return "", errors.Wrap(err, "error saving nonce")
	}
	return val, nil
}

// UseNonce verifies that the nonce is valid (by checking if it exists),
// and if so, consumes the nonce resource by deleting it from the database.
func UseNonce(db nosql.DB, nonce string) (bool, error) {
	err := db.Update(&database.Tx{
		Operations: []*database.TxEntry{
			&database.TxEntry{
				Bucket: nonceTable,
				Key:    []byte(nonce),
				Cmd:    database.Get,
			},
			&database.TxEntry{
				Bucket: nonceTable,
				Key:    []byte(nonce),
				Cmd:    database.Delete,
			},
		},
	})

	switch {
	case nosql.IsErrNotFound(err):
		return false, nil
	case err != nil:
		return false, errors.Wrapf(err, "error deleting nonce")
	default:
		return true, nil
	}
}
