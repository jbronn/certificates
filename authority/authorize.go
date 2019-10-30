package authority

import (
	"context"
	"crypto/x509"
	"net/http"
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/cli/jose"
)

// Claims extends jose.Claims with step attributes.
type Claims struct {
	jose.Claims
	SANs  []string `json:"sans,omitempty"`
	Email string   `json:"email,omitempty"`
	Nonce string   `json:"nonce,omitempty"`
}

// authorizeToken parses the token and returns the provisioner used to generate
// the token. This method enforces the One-Time use policy (tokens can only be
// used once).
func (a *Authority) authorizeToken(ott string) (provisioner.Interface, error) {
	var errContext = map[string]interface{}{"ott": ott}

	// Validate payload
	token, err := jose.ParseSigned(ott)
	if err != nil {
		return nil, &apiError{errors.Wrapf(err, "authorizeToken: error parsing token"),
			http.StatusUnauthorized, errContext}
	}

	// Get claims w/out verification. We need to look up the provisioner
	// key in order to verify the claims and we need the issuer from the claims
	// before we can look up the provisioner.
	var claims Claims
	if err = token.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, &apiError{errors.Wrap(err, "authorizeToken"), http.StatusUnauthorized, errContext}
	}

	// TODO: use new persistence layer abstraction.
	// Do not accept tokens issued before the start of the ca.
	// This check is meant as a stopgap solution to the current lack of a persistence layer.
	if a.config.AuthorityConfig != nil && !a.config.AuthorityConfig.DisableIssuedAtCheck {
		if claims.IssuedAt != nil && claims.IssuedAt.Time().Before(a.startTime) {
			return nil, &apiError{errors.New("authorizeToken: token issued before the bootstrap of certificate authority"),
				http.StatusUnauthorized, errContext}
		}
	}

	// This method will also validate the audiences for JWK provisioners.
	p, ok := a.provisioners.LoadByToken(token, &claims.Claims)
	if !ok {
		return nil, &apiError{
			errors.Errorf("authorizeToken: provisioner not found or invalid audience (%s)", strings.Join(claims.Audience, ", ")),
			http.StatusUnauthorized, errContext}
	}

	// Store the token to protect against reuse.
	if reuseKey, err := p.GetTokenID(ott); err == nil {
		ok, err := a.db.UseToken(reuseKey, ott)
		if err != nil {
			return nil, &apiError{errors.Wrap(err, "authorizeToken: failed when checking if token already used"),
				http.StatusInternalServerError, errContext}
		}
		if !ok {
			return nil, &apiError{errors.Errorf("authorizeToken: token already used"), http.StatusUnauthorized, errContext}
		}
	}

	return p, nil
}

// Authorize grabs the method from the context and authorizes a signature
// request by validating the one-time-token.
func (a *Authority) Authorize(ctx context.Context, ott string) ([]provisioner.SignOption, error) {
	var errContext = apiCtx{"ott": ott}
	switch m := provisioner.MethodFromContext(ctx); m {
	case provisioner.SignMethod:
		return a.authorizeSign(ctx, ott)
	case provisioner.SignSSHMethod:
		if a.sshCAHostCertSignKey == nil && a.sshCAUserCertSignKey == nil {
			return nil, &apiError{errors.New("authorize: ssh signing is not enabled"), http.StatusNotImplemented, errContext}
		}
		return a.authorizeSign(ctx, ott)
	case provisioner.RevokeMethod:
		return nil, &apiError{errors.New("authorize: revoke method is not supported"), http.StatusInternalServerError, errContext}
	default:
		return nil, &apiError{errors.Errorf("authorize: method %d is not supported", m), http.StatusInternalServerError, errContext}
	}
}

// authorizeSign loads the provisioner from the token, checks that it has not
// been used again and calls the provisioner AuthorizeSign method. Returns a
// list of methods to apply to the signing flow.
func (a *Authority) authorizeSign(ctx context.Context, ott string) ([]provisioner.SignOption, error) {
	var errContext = apiCtx{"ott": ott}
	p, err := a.authorizeToken(ott)
	if err != nil {
		return nil, &apiError{errors.Wrap(err, "authorizeSign"), http.StatusUnauthorized, errContext}
	}
	opts, err := p.AuthorizeSign(ctx, ott)
	if err != nil {
		return nil, &apiError{errors.Wrap(err, "authorizeSign"), http.StatusUnauthorized, errContext}
	}
	return opts, nil
}

// AuthorizeSign authorizes a signature request by validating and authenticating
// a OTT that must be sent w/ the request.
//
// NOTE: This method is deprecated and should not be used. We make it available
// in the short term os as not to break existing clients.
func (a *Authority) AuthorizeSign(ott string) ([]provisioner.SignOption, error) {
	ctx := provisioner.NewContextWithMethod(context.Background(), provisioner.SignMethod)
	return a.Authorize(ctx, ott)
}

// authorizeRevoke authorizes a revocation request by validating and authenticating
// the RevokeOptions POSTed with the request.
// Returns a tuple of the provisioner ID and error, if one occurred.
func (a *Authority) authorizeRevoke(opts *RevokeOptions) (p provisioner.Interface, err error) {
	if opts.MTLS {
		if opts.Crt.SerialNumber.String() != opts.Serial {
			return nil, errors.New("authorizeRevoke: serial number in certificate different than body")
		}
		// Load the Certificate provisioner if one exists.
		p, err = a.LoadProvisionerByCertificate(opts.Crt)
		if err != nil {
			return nil, errors.Wrap(err, "authorizeRevoke")
		}
	} else {
		// Gets the token provisioner and validates common token fields.
		p, err = a.authorizeToken(opts.OTT)
		if err != nil {
			return nil, errors.Wrap(err, "authorizeRevoke")
		}

		// Call the provisioner AuthorizeRevoke to apply provisioner specific auth claims.
		err = p.AuthorizeRevoke(opts.OTT)
		if err != nil {
			return nil, errors.Wrap(err, "authorizeRevoke")
		}
	}
	return
}

// authorizeRenewal tries to locate the step provisioner extension, and checks
// if for the configured provisioner, the renewal is enabled or not. If the
// extra extension cannot be found, authorize the renewal by default.
//
// TODO(mariano): should we authorize by default?
func (a *Authority) authorizeRenewal(crt *x509.Certificate) error {
	errContext := map[string]interface{}{"serialNumber": crt.SerialNumber.String()}

	// Check the passive revocation table.
	isRevoked, err := a.db.IsRevoked(crt.SerialNumber.String())
	if err != nil {
		return &apiError{
			err:     errors.Wrap(err, "renew"),
			code:    http.StatusInternalServerError,
			context: errContext,
		}
	}
	if isRevoked {
		return &apiError{
			err:     errors.New("renew: certificate has been revoked"),
			code:    http.StatusUnauthorized,
			context: errContext,
		}
	}

	p, ok := a.provisioners.LoadByCertificate(crt)
	if !ok {
		return &apiError{
			err:     errors.New("renew: provisioner not found"),
			code:    http.StatusUnauthorized,
			context: errContext,
		}
	}
	if err := p.AuthorizeRenewal(crt); err != nil {
		return &apiError{
			err:     errors.Wrap(err, "renew"),
			code:    http.StatusUnauthorized,
			context: errContext,
		}
	}
	return nil
}
