package acme

import (
	"encoding/json"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/randutil"
	"github.com/smallstep/cli/jose"
	"github.com/smallstep/nosql"
)

// Account represents an ACME account.
type Account struct {
	ID      string `json:"id"`
	Created time.Time
	Key     *jose.JSONWebKey `json:"key"`
	Contact []string         `json:"contact,omitempty"`
	Status  string           `json:"status"`
}

// AccountOptions are the options needed to create a new ACME account.
type AccountOptions struct {
	Key     *jose.JSONWebKey
	Contact []string
}

// NewAccount returns a new acme account type.
func NewAccount(db nosql.DB, ops AccountOptions) (*Account, error) {
	id, err := randutil.ASCII(idLen)
	if err != nil {
		return nil, errors.Wrap(err, "error generating random id for ACME account")
	}

	a := &Account{
		ID:      id,
		Key:     ops.Key,
		Contact: ops.Contact,
		Status:  "valid",
		Created: time.Now().UTC(),
	}

	if err := a.save(db, nil); err != nil {
		return nil, err
	}
	return a, nil
}

// GetAccountByKeyID retrieves Id associated with the given Kid.
func GetAccountByKeyID(db nosql.DB, kid string) (*Account, error) {
	id, err := db.Get(accountByKeyIDTable, []byte(kid))
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return GetAccountByID(db, string(id))
}

// GetAccountByID retrieves the account with the given ID.
func GetAccountByID(db nosql.DB, id string) (*Account, error) {
	var a Account

	ab, err := db.Get(accountTable, []byte(id))
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if err = json.Unmarshal(ab, &a); err != nil {
		return nil, errors.Wrap(err, "error unmarshaling acme account")
	}
	return &a, nil
}

// Save writes the Account to the DB.
// If the account is new then the necessary indices will be created.
// Else, the account in the DB will be updated.
func (a *Account) save(db nosql.DB, swp *Account) error {
	if swp != nil {
		return saveUpdate(db, a, swp)
	}

	jwkID := []byte(a.Key.KeyID)

	// Set the jwkID -> acme account ID index
	_, swapped, err := db.CmpAndSwap(accountByKeyIDTable, jwkID, nil, []byte(a.ID))
	if err != nil {
		return errors.Wrap(err, "error setting jwkID to acme account index")
	} else if !swapped {
		return errors.Errorf("jwkID to acme account index already has entry for jwkID %s", jwkID)
	}

	accB, err := json.Marshal(*a)
	if err != nil {
		return errors.Wrap(err, "error marshaling acme account object")
	}

	// Set the Account
	_, swapped, err = db.CmpAndSwap(accountTable, []byte(a.ID), nil, accB)
	if err != nil || !swapped {
		// Attempt to clean up previously added index
		db.Del(accountByKeyIDTable, jwkID)
		if err != nil {
			return errors.Wrap(err, "error setting new acme account")
		}
		return errors.Errorf("acme account with ID %s already exists", a.ID)
	}

	return nil
}

func saveUpdate(db nosql.DB, acc, swp *Account) error {
	swpB, err := json.Marshal(*swp)
	if err != nil {
		return errors.Wrap(err, "error marshaling acme account object")
	}

	accB, err := json.Marshal(*acc)
	if err != nil {
		return errors.Wrap(err, "error marshaling acme account object")
	}
	// Set the Account
	_, swapped, err := db.CmpAndSwap(accountTable, []byte(acc.ID), swpB, accB)
	if err != nil {
		return errors.Wrapf(err,
			"error updating account with ID %s", acc.ID)
	} else if !swapped {
		return errors.Wrapf(err,
			"error updating account; account with ID %s has changed since last read", acc.ID)
	}
	return nil
}

// Update updates the acme account object stored in the database if,
// and only if, the account has not changed since the last read.
func (a *Account) Update(db nosql.DB, contact []string) (*Account, error) {
	b := *a
	b.Contact = contact
	if err := (&b).save(db, a); err != nil {
		return nil, err
	}
	return &b, nil
}

// IsValid returns true is the Account is valid.
func (a *Account) IsValid() bool {
	return a.Status == statusValid
}

// ToACME converts the internal Account type into the public acmeAccount
// type for presentation in the ACME protocol.
func (a *Account) ToACME(db nosql.DB, dir *Directory) (interface{}, error) {
	return &acmeAccount{
		Status:  a.Status,
		Contact: a.Contact,
		Orders:  dir.GetOrdersByAccount(a.ID, true),
	}, nil
}

// acmeAccount is a subset of the Account type containing only those attributes
// required for responses in the ACME protocol.
type acmeAccount struct {
	Contact []string `json:"contact,omitempty"`
	Status  string   `json:"status"`
	Orders  string   `json:"orders"`
}
