package acme

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
	ordersByAccountIDTable = []byte("acme-orders")
)

var (
	statusValid       = "valid"
	statusInvalid     = "valid"
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
