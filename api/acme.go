package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"github.com/pkg/errors"
	"github.com/smallstep/certificates/api/acme"
	"github.com/smallstep/cli/jose"
	"github.com/smallstep/nosql"
)

type acmeHandler struct {
	db     nosql.DB
	Dir    *acme.Directory
	domain string
	prefix string
}

// newACMEHandler returns a new acmeHandler type.
func newACMEHandler(db nosql.DB, domain, prefix string, dirOpts *acme.DirectoryOptions) *acmeHandler {
	dir := acme.NewDirectory(domain, prefix, dirOpts)
	return &acmeHandler{db, dir, domain, prefix}
}

type contextKey string

const (
	jwsContextKey     = contextKey("jws")
	jwkContextKey     = contextKey("jwk")
	payloadContextKey = contextKey("payload")
	accContextKey     = contextKey("acc")
)

// NewAccountRequest represents the payload for a new account request.
type NewAccountRequest struct {
	Contact            []string
	OnlyReturnExisting bool
}

// Validate validates a new-account request body.
func (n *NewAccountRequest) Validate() error {
	if n.Contact != nil {
		// TODO: Check contacts.
	}
	return nil
}

// UpdateAccountRequest represents an update-account request.
type UpdateAccountRequest struct {
	Contact []string
	Status  string
}

// IsDeactivateRequest returns true if the update request is a deactivation
// request, false otherwise.
func (u *UpdateAccountRequest) IsDeactivateRequest() bool {
	return u.Contact == nil && u.Status == "deactivated"
}

// Validate validates a update-account request body.
func (u *UpdateAccountRequest) Validate() error {
	// Regular update //
	switch {
	case u.Contact != nil:
		// TODO: Check contacts.
		return nil
	case len(u.Status) > 0:
		if u.Status != "deactivated" {
			return BadRequest(errors.Errorf("cannot update account status to %s, only deactivated", u.Status))
		}
		return nil
	default:
		return BadRequest(errors.Errorf("empty update request"))
	}
}

// NewOrderRequest represents the body for a NewOrder request.
type NewOrderRequest struct {
	Identifiers []acme.Identifier `json:"identifiers"`
	NotBefore   time.Time         `json:"notBefore"`
	NotAfter    time.Time         `json:"notAfter"`
}

// Validate validates a new-order request body.
func (n *NewOrderRequest) Validate() error {
	if len(n.Identifiers) == 0 {
		return BadRequest(errors.Errorf("identifiers list cannot be empty"))
	}
	for _, id := range n.Identifiers {
		if id.Type != "dns" {
			return BadRequest(errors.Errorf("identifier type unsupported: %s", id.Type))
		}
	}
	now := time.Now().UTC()
	if n.NotBefore.IsZero() {
		n.NotBefore = now
	}
	if n.NotAfter.IsZero() {
		n.NotAfter = now.Add(time.Hour * 24)
	}
	if now.After(n.NotAfter) {
		return BadRequest(errors.Errorf("NotAfter is already in the past: %s", n.NotAfter))
	}
	if n.NotBefore.After(n.NotAfter) {
		return BadRequest(errors.Errorf("NotAfter is before NotBefore - NotBefore: %s, NotAfter: %s", n.NotBefore, n.NotAfter))
	}
	return nil
}

type payloadInfo struct {
	value       []byte
	isPostAsGet bool
	isEmptyJSON bool
}

func payloadFromContext(r *http.Request) (val *payloadInfo, ok bool) {
	val, ok = r.Context().Value(payloadContextKey).(*payloadInfo)
	return
}
func accountFromContext(r *http.Request) (val *acme.Account, ok bool) {
	val, ok = r.Context().Value(accContextKey).(*acme.Account)
	return
}
func jwkFromContext(r *http.Request) (val *jose.JSONWebKey, ok bool) {
	val, ok = r.Context().Value(jwkContextKey).(*jose.JSONWebKey)
	return
}
func jwsFromContext(r *http.Request) (val *jose.JSONWebSignature, ok bool) {
	fmt.Printf("r.Context() = %+v\n", r.Context())
	val, ok = r.Context().Value(jwsContextKey).(*jose.JSONWebSignature)
	return
}

type nextHTTP = func(http.ResponseWriter, *http.Request)

func (a *acmeHandler) addNonce(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		nonce, err := acme.NewNonce(a.db)
		if err != nil {
			WriteError(w, InternalServerError(errors.Wrap(err, "failed creating nonce")))
			return
		}
		w.Header().Set("Replay-Nonce", nonce)
		w.Header().Set("Cache-Control", "no-store")
		next(w, r)
		return
	}
}

// verifyContentType verifies that content type is application/jose+json
func (a *acmeHandler) verifyContentType(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		expected := "application/jose+json"
		contentType := r.Header.Get("Content-Type")
		if contentType != expected {
			WriteError(w, BadRequest(errors.Errorf(
				"expected content-type %s, but got %s", expected, contentType)))
			return
		}
		next(w, r)
		return
	}
}

// parseJWS parses a request body into a JSONWebSignature struct.
func (a *acmeHandler) parseJWS(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			WriteError(w, InternalServerError(errors.Wrap(err, "failed to read request body")))
			return
		}
		jws, err := jose.ParseJWS(string(body))
		if err != nil {
			WriteError(w, BadRequest(errors.Wrap(err, "failed to parse JWS from request body")))
			return
		}
		ctx := context.WithValue(r.Context(), jwsContextKey, jws)
		next(w, r.WithContext(ctx))
		return
	}
}

// The JWS MUST NOT have multiple signatures
// The JWS Unencoded Payload Option [RFC7797] MUST NOT be used
// The JWS Unprotected Header [RFC7515] MUST NOT be used
// The JWS Payload MUST NOT be detached
// The JWS Protected Header MUST include the following fields:
//   * “alg” (Algorithm)
//     * This field MUST NOT contain “none” or a Message Authentication Code
//       (MAC) algorithm (e.g. one in which the algorithm registry description
//       mentions MAC/HMAC).
//   * “nonce” (defined in Section 6.5)
//   * “url” (defined in Section 6.4)
//   * Either “jwk” (JSON Web Key) or “kid” (Key ID) as specified below<Paste>
func (a *acmeHandler) validateJWS(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		jws, ok := jwsFromContext(r)
		if !ok || jws == nil {
			WriteError(w, InternalServerError(errors.Errorf("jws not in request context")))
			return
		}
		if len(jws.Signatures) == 0 {
			WriteError(w, BadRequest(errors.Errorf("request body does not contain a signature")))
			return
		}
		if len(jws.Signatures) > 1 {
			WriteError(w, BadRequest(errors.Errorf("request body contains more than one signature")))
			return
		}

		sig := jws.Signatures[0]
		uh := sig.Unprotected
		if len(uh.KeyID) > 0 ||
			uh.JSONWebKey != nil ||
			len(uh.Algorithm) > 0 ||
			len(uh.Nonce) > 0 ||
			len(uh.ExtraHeaders) > 0 {
			WriteError(w, BadRequest(errors.Errorf("unprotected header must not be used")))
			return
		}
		hdr := sig.Protected
		if hdr.Algorithm == "none" {
			WriteError(w, BadRequest(errors.Errorf("algorithm cannot be none")))
			return
		}

		// Check the freshness of the Nonce.
		ok, err := acme.UseNonce(a.db, hdr.Nonce)
		if err != nil {
			WriteError(w, InternalServerError(errors.Errorf("nonce not found")))
			return
		}
		if !ok {
			WriteError(w, Unauthorized(errors.Errorf("unauthorized nonce")))
			return
		}

		// Check that the JWS url matches the requested url.
		url, ok := hdr.ExtraHeaders["url"].(string)
		if !ok || len(url) == 0 {
			WriteError(w, BadRequest(errors.Errorf("JWS missing url protected header")))
			return
		}
		if url != r.URL.String() {
			WriteError(w, BadRequest(errors.Errorf("protected url header in JWS does not match request url")))
			return
		}

		if hdr.JSONWebKey != nil && len(hdr.KeyID) > 0 {
			WriteError(w, BadRequest(errors.Errorf("jwk and kid are mutually exclusive")))
			return
		}
		if hdr.JSONWebKey == nil && len(hdr.KeyID) == 0 {
			WriteError(w, BadRequest(errors.Errorf("either jwk or kid must be defined in jws protected header")))
			return
		}
		next(w, r)
		return
	}
}

// extractJWK extracts the JWK from the JWS and saves it in the context.
// Make sure to parse and validate the JWS before running this middleware.
func (a *acmeHandler) extractJWK(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		jws, ok := jwsFromContext(r)
		if !ok || jws == nil {
			WriteError(w, InternalServerError(errors.Errorf("jws not in request context")))
			return
		}
		jwk := jws.Signatures[0].Protected.JSONWebKey
		if jwk == nil {
			WriteError(w, BadRequest(errors.Errorf("expected jwk in protected header")))
			return
		}
		ctx := context.WithValue(r.Context(), jwkContextKey, jwk)

		acc, err := acme.GetAccountByKeyID(a.db, jwk.KeyID)
		switch {
		case nosql.IsErrNotFound(err):
			// do nothing
		case err != nil:
			WriteError(w, errors.Wrap(err, "error when loading account by jwk index"))
			return
		default:
			if acc.Status != "valid" {
				WriteError(w, Unauthorized(errors.New("acme account is not active")))
				return
			}
			ctx = context.WithValue(r.Context(), accContextKey, acc)
		}

		next(w, r.WithContext(ctx))
		return
	}
}

// lookupJWK loads the JWK associated with the acme account referenced by the
// kid parameter of the signed payload.
// Make sure to parse and validate the JWS before running this middleware.
func (a *acmeHandler) lookupJWK(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {

		jws, ok := jwsFromContext(r)
		if !ok || jws == nil {
			WriteError(w, InternalServerError(errors.Errorf("jws not in request context")))
			return
		}

		url := "https://ca.smallstep.com:8080/account/"
		kid := jws.Signatures[0].Protected.KeyID
		if !strings.HasPrefix(kid, url) {
			WriteError(w, BadRequest(errors.Errorf("expected jwk in protected header")))
			return
		}

		accID := strings.TrimPrefix(kid, url)
		ctx := r.Context()

		acc, err := acme.GetAccountByID(a.db, accID)
		switch {
		case nosql.IsErrNotFound(err):
			WriteError(w, BadRequest(errors.Errorf("acme account with ID %s not found", accID)))
			return
		case err != nil:
			WriteError(w, errors.Wrap(err, "error when loading account id"))
			return
		default:
			if acc.Status != "valid" {
				WriteError(w, Unauthorized(errors.New("acme account is not active")))
				return
			}
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, jwkContextKey, acc.Key)
		}

		next(w, r.WithContext(ctx))
		return
	}
}

// verifyAndExtractJWSPayload extracts the JWK from the JWS and saves it in the context.
// Make sure to parse and validate the JWS before running this middleware.
func (a *acmeHandler) verifyAndExtractJWSPayload(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		jws, ok := jwsFromContext(r)
		if !ok || jws == nil {
			WriteError(w, InternalServerError(errors.Errorf("jws not in request context")))
			return
		}
		jwk, ok := r.Context().Value(jwkContextKey).(*jose.JSONWebKey)
		if !ok || jwk == nil {
			WriteError(w, InternalServerError(errors.Errorf("jwk not in request context")))
			return
		}
		payload, err := jws.Verify(jwk)
		if err != nil {
			WriteError(w, BadRequest(errors.Errorf("failed to verify jws")))
			return
		}
		ctx := context.WithValue(r.Context(), payloadContextKey, &payloadInfo{
			value:       payload,
			isPostAsGet: string(payload) == "",
			isEmptyJSON: string(payload) == "{}",
		})
		next(w, r.WithContext(ctx))
		return
	}
}

// GetNonce just sets the right header since a Nonce is added to each response
// by middleware by default.
func (a *acmeHandler) GetNonce(w http.ResponseWriter, r *http.Request) {
	if r.Method == "HEAD" {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusNoContent)
	}
	return
}

func (a *acmeHandler) GetDirectory(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	JSON(w, a.Dir.ToACME())
}

func (a *acmeHandler) NewAccount(w http.ResponseWriter, r *http.Request) {
	payload, ok := payloadFromContext(r)
	if !ok || payload == nil {
		WriteError(w, InternalServerError(errors.Errorf("payload not in request context")))
		return
	}
	var nar NewAccountRequest
	if err := json.Unmarshal(payload.value, &nar); err != nil {
		WriteError(w, InternalServerError(errors.Wrap(err,
			"failed to unmarshal new-account request payload")))
		return
	}

	if err := nar.Validate(); err != nil {
		WriteError(w, err)
		return
	}

	acc, ok := accountFromContext(r)
	if !ok {
		// Account does not exist //
		if nar.OnlyReturnExisting {
			WriteError(w, BadRequest(errors.Errorf("account does not exist")))
			return
		}
		jwk, ok := jwkFromContext(r)
		if !ok || jwk == nil {
			WriteError(w, InternalServerError(errors.Errorf("jwk not in request context")))
			return
		}

		var err error
		if acc, err = acme.NewAccount(a.db, acme.AccountOptions{
			Key:     jwk,
			Contact: nar.Contact,
		}); err != nil {
			WriteError(w, BadRequest(errors.Errorf("error creating acme account")))
			return
		}
		w.WriteHeader(http.StatusCreated)
	} else {
		// Account exists //
		w.WriteHeader(http.StatusOK)
	}

	out, err := acc.ToACME(a.db, a.Dir)
	if err != nil {
		WriteError(w, InternalServerError(errors.Wrapf(err, "error converting account to acmeAccount")))
		return
	}
	w.Header().Set("Location", a.Dir.GetAccount(acc.ID, true))
	JSON(w, out)
	return
}

// UpdateAccount is the api for updating an ACME account.
func (a *acmeHandler) UpdateAccount(w http.ResponseWriter, r *http.Request) {
	acc, ok := accountFromContext(r)
	if !ok || acc == nil {
		// Account does not exist //
		WriteError(w, NotFound(errors.Errorf("account not found")))
		return
	}
	payload, ok := payloadFromContext(r)
	if !ok || payload == nil {
		WriteError(w, InternalServerError(errors.Errorf("payload not in request context")))
		return
	}

	if !payload.isPostAsGet {
		var uar UpdateAccountRequest
		if err := json.Unmarshal(payload.value, &uar); err != nil {
			WriteError(w, InternalServerError(errors.Wrap(err, "failed to unmarshal new-account request payload")))
			return
		}

		if err := uar.Validate(); err != nil {
			WriteError(w, err)
			return
		}

		var err error
		if uar.IsDeactivateRequest() {
			// TODO
			//acc, err = acc.Deactivate(a.db)
		} else {
			acc, err = acc.Update(a.db, uar.Contact)
		}
		if err != nil {
			WriteError(w, InternalServerError(errors.Wrapf(err, "error updating account")))
			return
		}

	}
	out, err := acc.ToACME(a.db, a.Dir)
	if err != nil {
		WriteError(w, InternalServerError(errors.Wrapf(err, "error converting account to acmeAccount")))
		return
	}

	w.WriteHeader(http.StatusOK)
	JSON(w, out)
	return
}

// NewOrder ACME api for creating a new order.
func (a *acmeHandler) NewOrder(w http.ResponseWriter, r *http.Request) {
	acc, ok := accountFromContext(r)
	if !ok || acc == nil {
		// Account does not exist //
		WriteError(w, Unauthorized(errors.Errorf("account not found")))
		return
	}
	if !acc.IsValid() {
		WriteError(w, Unauthorized(errors.Errorf("account is not valid")))
		return
	}

	payload, ok := payloadFromContext(r)
	if !ok || payload == nil {
		WriteError(w, InternalServerError(errors.Errorf("payload not in request context")))
		return
	}
	var nor NewOrderRequest
	if err := json.Unmarshal(payload.value, &nor); err != nil {
		WriteError(w, InternalServerError(errors.Wrap(err,
			"failed to unmarshal new-account request payload")))
		return
	}

	if err := nor.Validate(); err != nil {
		WriteError(w, err)
		return
	}

	order, err := acme.NewOrder(a.db, acme.OrderOptions{
		AccountID:   acc.ID,
		Identifiers: nor.Identifiers,
		NotBefore:   nor.NotBefore,
		NotAfter:    nor.NotAfter,
	})
	if err != nil {
		WriteError(w, InternalServerError(errors.Wrap(err,
			"error creating order")))
		return
	}

	out, err := order.ToACME(a.db, a.Dir)
	if err != nil {
		WriteError(w, InternalServerError(errors.Wrapf(err, "error converting order to acmeOrder")))
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Header().Set("Location", a.Dir.GetOrder(acc.ID, true))
	JSON(w, out)
	return
}

// GetOrder ACME api for retrieving an order.
func (a *acmeHandler) GetOrder(w http.ResponseWriter, r *http.Request) {
	acc, ok := accountFromContext(r)
	if !ok || acc == nil {
		// Account does not exist //
		WriteError(w, Unauthorized(errors.Errorf("account not found")))
		return
	}
	if !acc.IsValid() {
		WriteError(w, Unauthorized(errors.Errorf("account is not valid")))
		return
	}

	payload, ok := payloadFromContext(r)
	if !ok || payload == nil {
		WriteError(w, InternalServerError(errors.Errorf("payload not in request context")))
		return
	}

	if !payload.isPostAsGet {
		WriteError(w, BadRequest(errors.Errorf("expected POST-as-GET; empty body")))
		return
	}

	oid := chi.URLParam(r, "ordID")
	order, err := acme.GetOrder(a.db, oid)
	if err != nil {
		WriteError(w, InternalServerError(errors.Wrapf(err, "error retrieving order %s", oid)))
		return
	}

	if order.AccountID != acc.ID {
		WriteError(w, Unauthorized(errors.Wrap(err, "account is not the owner of the order")))
		return
	}

	if order, err = order.UpdateStatus(a.db); err != nil {
		WriteError(w, InternalServerError(errors.Wrap(err, "error updating order status")))
		return
	}

	out, err := order.ToACME(a.db, a.Dir)
	if err != nil {
		WriteError(w, InternalServerError(errors.Wrapf(err, "error converting order to acmeOrder")))
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Location", a.Dir.GetOrder(order.ID, true))
	JSON(w, out)
	return
}

// GetAuthz ACME api for retrieving an Authz.
func (a *acmeHandler) GetAuthz(w http.ResponseWriter, r *http.Request) {
	acc, ok := accountFromContext(r)
	if !ok || acc == nil {
		// Account does not exist //
		WriteError(w, Unauthorized(errors.Errorf("account not found")))
		return
	}
	if !acc.IsValid() {
		WriteError(w, Unauthorized(errors.Errorf("account is not valid")))
		return
	}

	payload, ok := payloadFromContext(r)
	if !ok || payload == nil {
		WriteError(w, InternalServerError(errors.Errorf("payload not in request context")))
		return
	}

	aid := chi.URLParam(r, "authzID")
	authz, err := acme.GetAuthz(a.db, aid)
	if err != nil {
		WriteError(w, InternalServerError(errors.Wrapf(err, "error retrieving authz %s", aid)))
		return
	}

	if authz.GetAccountID() != acc.ID {
		WriteError(w, Unauthorized(errors.Wrap(err, "account is not the owner of the authz")))
		return
	}

	if !payload.isPostAsGet {
		WriteError(w, InternalServerError(errors.Wrap(err, "unimplemented")))
		return
	}

	out, err := authz.ToACME(a.db, a.Dir)
	if err != nil {
		WriteError(w, InternalServerError(errors.Wrapf(err, "error converting order to acmeOrder")))
		return
	}
	w.WriteHeader(http.StatusCreated)
	w.Header().Set("Location", a.Dir.GetOrder(authz.GetID(), true))
	JSON(w, out)
	return
}

// GetChallenge ACME api for retrieving a Challenge.
func (a *acmeHandler) GetChallenge(w http.ResponseWriter, r *http.Request) {
	acc, ok := accountFromContext(r)
	if !ok || acc == nil {
		// Account does not exist //
		WriteError(w, Unauthorized(errors.Errorf("account not found")))
		return
	}
	if !acc.IsValid() {
		WriteError(w, Unauthorized(errors.Errorf("account is not valid")))
		return
	}

	payload, ok := payloadFromContext(r)
	if !ok || payload == nil {
		WriteError(w, InternalServerError(errors.Errorf("payload not in request context")))
		return
	}

	if !(payload.isPostAsGet || payload.isEmptyJSON) {
		WriteError(w, BadRequest(errors.Errorf("unexpected payload")))
		return
	}

	// Load the challenge.
	chID := chi.URLParam(r, "chID")
	ch, err := acme.GetChallenge(a.db, chID)
	if err != nil {
		WriteError(w, InternalServerError(errors.Wrapf(err, "error retrieving challenge %s", chID)))
		return
	}

	// Verify that challenge owner matches account id making the request.
	if ch.GetAccountID() != acc.ID {
		WriteError(w, Unauthorized(errors.Wrap(err, "account is not the owner of the authz")))
		return
	}

	// If empty JSON payload then attempt to validate the challenge.
	if payload.isEmptyJSON {
		var isValid bool
		ch, isValid, err = ch.Validate(a.db, acc.Key)
		if err != nil {
			WriteError(w, InternalServerError(errors.Wrap(err, "error updating challenge status")))
			return
		}
		if !isValid {
			WriteError(w, BadRequest(errors.New("unable to validate challenge")))
			return
		}
	}

	out, err := ch.ToACME(a.db, a.Dir)
	if err != nil {
		WriteError(w, InternalServerError(errors.Wrapf(err, "error converting order to acmeOrder")))
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Location", a.Dir.GetChallenge(ch.GetID(), true))
	JSON(w, out)
	return
}
