package acme

import "fmt"

// Directory represents an ACME directory for configuring clients.
type Directory struct {
	NewNonce   string
	NewAccount string
	NewOrder   string
	NewAuthz   string
	RevokeCert string
	KeyChange  string
	Directory  string
	prefix     string
	dns        string
	ops        *DirectoryOptions
}

// DirectoryOptions options with which to create a new Directory type.
type DirectoryOptions struct {
	Nonce       string
	NewNonce    string
	Account     string
	NewAccount  string
	Order       string
	NewOrder    string
	Authz       string
	NewAuthz    string
	Challenge   string
	RevokeCert  string
	KeyChange   string
	Certificate string
	Directory   string
}

var defaultDirOptions = DirectoryOptions{
	Nonce:       "nonce",
	NewNonce:    "new-nonce",
	Account:     "account",
	NewAccount:  "new-account",
	Order:       "order",
	NewOrder:    "new-order",
	Authz:       "authz",
	NewAuthz:    "new-authz",
	Challenge:   "challenge",
	RevokeCert:  "revoke-cert",
	KeyChange:   "key-change",
	Certificate: "cert",
	Directory:   "directory",
}

// NewDirectory returns a new Direcotyr type.
func NewDirectory(dns, prefix string, ops *DirectoryOptions) *Directory {
	if ops == nil {
		ops = &defaultDirOptions
	}

	return &Directory{
		prefix:     prefix,
		dns:        dns,
		ops:        ops,
		NewNonce:   fmt.Sprintf("/%s/%s", prefix, ops.NewNonce),
		NewAccount: fmt.Sprintf("/%s/%s", prefix, ops.NewAccount),
		NewOrder:   fmt.Sprintf("/%s/%s", prefix, ops.NewOrder),
		NewAuthz:   fmt.Sprintf("/%s/%s", prefix, ops.NewAuthz),
		RevokeCert: fmt.Sprintf("/%s/%s", prefix, ops.RevokeCert),
		KeyChange:  fmt.Sprintf("/%s/%s", prefix, ops.KeyChange),
		Directory:  fmt.Sprintf("/%s/%s", prefix, ops.Directory),
	}
}

// GetAccount returns the location for retrieving Account info by ID.
func (d *Directory) GetAccount(id string, abs bool) string {
	p := fmt.Sprintf("/%s/%s/%s", d.prefix, d.ops.Account, id)
	if abs {
		p = fmt.Sprintf("https://%s%s", d.dns, p)
	}
	return p
}

// GetOrder returns the location for retrieving Order info by ID.
func (d *Directory) GetOrder(id string, abs bool) string {
	p := fmt.Sprintf("/%s/%s/%s", d.prefix, d.ops.Order, id)
	if abs {
		p = fmt.Sprintf("https://%s%s", d.dns, p)
	}
	return p
}

// GetAuthz returns the location for retrieving Authz info by ID.
func (d *Directory) GetAuthz(id string, abs bool) string {
	p := fmt.Sprintf("/%s/%s/%s", d.prefix, d.ops.Authz, id)
	if abs {
		p = fmt.Sprintf("https://%s%s", d.dns, p)
	}
	return p
}

// GetChallenge returns the location for retrieving Challenge info by ID.
func (d *Directory) GetChallenge(id string, abs bool) string {
	p := fmt.Sprintf("/%s/%s/%s", d.prefix, d.ops.Challenge, id)
	if abs {
		p = fmt.Sprintf("https://%s%s", d.dns, p)
	}
	return p
}

// GetFinalize returns the location for finalizing an Order by ID.
func (d *Directory) GetFinalize(id string, abs bool) string {
	return fmt.Sprintf("%s/finalize", d.GetOrder(id, abs))
}

// GetOrdersByAccount returns the location for retrieving a list of orders
// belonging to an Account.
func (d *Directory) GetOrdersByAccount(id string, abs bool) string {
	return fmt.Sprintf("%s/orders", d.GetAccount(id, abs))
}

// GetCertificate returns the location for retrieving a Certificate by ID.
func (d *Directory) GetCertificate(id string, abs bool) string {
	p := fmt.Sprintf("/%s/%s/%s", d.prefix, d.ops.Certificate, id)
	if abs {
		p = fmt.Sprintf("https://%s%s", d.dns, p)
	}
	return p
}

// GetDirectory returns the location for retrieving the directory index.
func (d *Directory) GetDirectory(abs bool) string {
	p := fmt.Sprintf("/%s/%s", d.prefix, d.ops.Directory)
	if abs {
		p = fmt.Sprintf("https://%s%s", d.dns, p)
	}
	return p
}

type acmeDirectory struct {
	NewNonce   string `json:"newNonce,omitempty"`
	NewAccount string `json:"newAccount,omitempty"`
	NewOrder   string `json:"newOrder,omitempty"`
	NewAuthz   string `json:"newAuthz,omitempty"`
	RevokeCert string `json:"revokeCert,omitempty"`
	KeyChange  string `json:"keyChange,omitempty"`
}

// ToACME returns an ACME representation for the internal Directory type.
func (d *Directory) ToACME() interface{} {
	return acmeDirectory{
		NewNonce:   fmt.Sprintf("https://%s/%s/%s", d.dns, d.prefix, d.ops.NewNonce),
		NewAccount: fmt.Sprintf("https://%s/%s/%s", d.dns, d.prefix, d.ops.NewAccount),
		NewOrder:   fmt.Sprintf("https://%s/%s/%s", d.dns, d.prefix, d.ops.NewOrder),
		RevokeCert: fmt.Sprintf("https://%s/%s/%s", d.dns, d.prefix, d.ops.RevokeCert),
		KeyChange:  fmt.Sprintf("https://%s/%s/%s", d.dns, d.prefix, d.ops.KeyChange),
	}
}
