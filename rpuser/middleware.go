package rpuser

import (
	"context"
	"errors"
	"net/http"

	"github.com/infodancer/oidclient"
	"github.com/infodancer/oidclient/session"
)

// Authenticator is the slice of *session.Manager the middleware needs: resolve
// a request's session to validated claims. The concrete manager satisfies it;
// tests substitute a fake.
type Authenticator interface {
	Authenticate(r *http.Request) (*oidclient.Claims, error)
}

var _ Authenticator = (*session.Manager)(nil)

// Middleware is the per-request half of the policy: resolve the session to
// claims, the claims to the host's user row (read-only), and stash identity,
// user, and claims in the request context for downstream handlers -- including
// the host's authz identity source.
//
// It is optional-auth by design: it never blocks a request. Anonymous, expired,
// and failed resolutions all proceed without context values, and route-level
// gating stays with the host (which knows whether a 401 should redirect,
// render, or JSON). Host-specific context enrichment (module user types, role
// resolution) composes as an ordinary wrapping middleware reading
// [IdentityFromContext] and [UserFromContext].
type Middleware struct {
	// Authenticator resolves the session cookie to claims; nil (sessions not
	// configured) makes every request anonymous, mirroring the optional-auth
	// contract.
	Authenticator Authenticator

	// Store resolves (issuer, subject) to the host's user row.
	Store UserStore

	// Issuer is the client's configured issuer URL, as in [Provisioner].
	Issuer string

	// Logf receives diagnostics for faults worth surfacing: a failed session
	// resolution (other than the expected no-session case) and a live session
	// whose subject has no user row. Nil disables logging.
	Logf func(format string, args ...any)
}

func (m *Middleware) logf(format string, args ...any) {
	if m.Logf != nil {
		m.Logf(format, args...)
	}
}

// Optional wraps next with the per-request resolution described on
// [Middleware]. Renewal happens inside Authenticate: the session manager
// transparently spends the refresh token when the access token nears expiry,
// so a session lasts its absolute TTL rather than one access-token window.
func (m *Middleware) Optional(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.Authenticator == nil {
			next.ServeHTTP(w, r)
			return
		}

		claims, err := m.Authenticator.Authenticate(r)
		if err != nil {
			// ErrNoSession is the expected unauthenticated case; anything else
			// (a failed renewal, a transient store error) is logged so a real
			// fault is diagnosable rather than a silent anonymous fallthrough.
			if !errors.Is(err, session.ErrNoSession) {
				m.logf("oidclient/rpuser: session authenticate: %v", err)
			}
			next.ServeHTTP(w, r)
			return
		}

		id := FromClaims(m.Issuer, claims)
		u, err := m.Store.LookupBySubject(r.Context(), id.Issuer, id.Subject)
		if err != nil {
			// A live session whose subject has no row (or a store fault) is
			// anomalous; log it and proceed anonymous rather than failing the
			// request.
			m.logf("oidclient/rpuser: lookup subject %s: %v (proceeding anonymous)", id.Subject, err)
			next.ServeHTTP(w, r)
			return
		}

		ctx := WithIdentity(r.Context(), &id)
		ctx = WithUser(ctx, &u)
		ctx = WithClaims(ctx, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type identityContextKey struct{}
type userContextKey struct{}
type claimsContextKey struct{}

// WithIdentity stores a resolved identity in the context. Exported for host
// tests; [Middleware.Optional] is the production writer.
func WithIdentity(ctx context.Context, id *Identity) context.Context {
	return context.WithValue(ctx, identityContextKey{}, id)
}

// IdentityFromContext returns the authenticated identity, or nil for an
// anonymous request. This is what a host's authz identity source should read.
func IdentityFromContext(ctx context.Context) *Identity {
	id, _ := ctx.Value(identityContextKey{}).(*Identity)
	return id
}

// WithUser stores a resolved user in the context. Exported for host tests;
// [Middleware.Optional] is the production writer.
func WithUser(ctx context.Context, u *User) context.Context {
	return context.WithValue(ctx, userContextKey{}, u)
}

// UserFromContext returns the resolved local user, or nil for an anonymous
// request. Hosts typically unwrap their own row from User.Host.
func UserFromContext(ctx context.Context) *User {
	u, _ := ctx.Value(userContextKey{}).(*User)
	return u
}

// WithClaims stores validated claims in the context. Exported for host tests;
// [Middleware.Optional] is the production writer.
func WithClaims(ctx context.Context, c *oidclient.Claims) context.Context {
	return context.WithValue(ctx, claimsContextKey{}, c)
}

// ClaimsFromContext returns the request's validated claims, or nil for an
// anonymous request.
func ClaimsFromContext(ctx context.Context) *oidclient.Claims {
	c, _ := ctx.Value(claimsContextKey{}).(*oidclient.Claims)
	return c
}
