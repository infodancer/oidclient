package rpuser

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

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

// Rechecker is the optional second slice of *session.Manager: renew a
// session's claims early, at most once per minInterval. The middleware uses it
// only for a user whose stored row is unverified; an Authenticator that does
// not implement it simply never rechecks.
type Rechecker interface {
	Recheck(r *http.Request, minInterval time.Duration) (*oidclient.Claims, error)
}

var _ Rechecker = (*session.Manager)(nil)

// DefaultUnverifiedRecheck is how often an unverified user's session asks the
// provider again when [Middleware.UnverifiedRecheck] is zero.
const DefaultUnverifiedRecheck = 5 * time.Minute

// Middleware is the per-request half of the policy: resolve the session to
// claims, the claims to the host's user row, and stash identity, user, and
// claims in the request context for downstream handlers -- including the
// host's authz identity source.
//
// The lookup is read-only for a verified row. For an unverified row it does
// one more thing, described on [Middleware.UnverifiedRecheck]: it promotes the
// row once the provider says the address is verified.
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

	// UnverifiedRecheck is how often the session of a user whose stored row is
	// unverified asks the provider for fresh claims. Zero means
	// [DefaultUnverifiedRecheck]; negative turns the early recheck off.
	//
	// The problem it answers: email verification happens at the provider,
	// usually minutes after sign-up and often in another browser, while the row
	// was written at sign-in and the session's claims are as old as its access
	// token. Left alone the user stays unverified here until they sign in
	// again. So, for an unverified row only:
	//
	//   - if the session's claims do not say verified and the Authenticator is
	//     a [Rechecker], it is asked for claims no older than this interval;
	//   - if the claims then say verified and name the address they mean, the
	//     row is promoted through UserStore.SyncEmail -- that address together
	//     with the flag -- and re-read. Claims that say verified but carry no
	//     address are not acted on;
	//   - a promotion the store refuses is not retried until the interval has
	//     passed.
	//
	// This is the backstop, not the main route: a host should send the user
	// back through sign-in when they finish verifying, which syncs at once.
	// Promotion is one-way and happens once per user; nothing here lowers the
	// flag, changes a verified row, or creates one. A verified user costs
	// nothing extra.
	UnverifiedRecheck time.Duration

	// Logf receives diagnostics for faults worth surfacing: a failed session
	// resolution (other than the expected no-session case), a live session
	// whose subject has no user row, and a failed recheck or promotion. Nil
	// disables logging.
	Logf func(format string, args ...any)

	// retry holds back a promotion write that just failed. Its presence means
	// a Middleware must be used through a pointer and not copied once in use.
	retry retryLog
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

		if !u.EmailVerified {
			claims, id, u = m.promote(r, claims, id, u)
		}

		ctx := WithIdentity(r.Context(), &id)
		ctx = WithUser(ctx, &u)
		ctx = WithClaims(ctx, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// attestsVerified reports whether the claims attest a verified address.
// email_verified describes the address in the same claims; with no address
// there is nothing it is true of, and acting on it would mark whatever address
// the row already holds as verified.
func attestsVerified(c *oidclient.Claims) bool {
	return c.EmailVerified && c.Email != ""
}

// promote is the unverified-row path described on
// [Middleware.UnverifiedRecheck]. It returns the claims, identity and user the
// request should proceed with: the promoted ones on success, the ones it was
// given on any fault. No fault here costs the request its user.
func (m *Middleware) promote(r *http.Request, claims *oidclient.Claims, id Identity, u User) (*oidclient.Claims, Identity, User) {
	interval := m.UnverifiedRecheck
	if interval == 0 {
		interval = DefaultUnverifiedRecheck
	}

	// A write that failed a moment ago is not retried until the interval has
	// passed. Claims that already say verified skip the recheck below and its
	// throttle, so without this a store that is down takes a failed write, and
	// a log line, on every request the user makes.
	now := time.Now()
	if m.retry.blocked(u.Key, now) {
		return claims, id, u
	}

	given, givenID := claims, id
	if !attestsVerified(claims) {
		rc, ok := m.Authenticator.(Rechecker)
		if !ok || interval < 0 {
			return claims, id, u
		}
		fresh, err := rc.Recheck(r, interval)
		if err != nil {
			m.logf("oidclient/rpuser: recheck unverified subject %s: %v", id.Subject, err)
			return claims, id, u
		}
		// The session cannot change hands between two reads of it; refuse to
		// act on the answer if it somehow did.
		if fresh.Sub != claims.Sub {
			m.logf("oidclient/rpuser: recheck for subject %s answered for another subject; ignored", id.Subject)
			return claims, id, u
		}
		if !attestsVerified(fresh) {
			return claims, id, u
		}
		claims, id = fresh, FromClaims(m.Issuer, fresh)
	}

	// The flag and the address it describes are written together. id.Email is
	// non-empty here: attestsVerified required it.
	if err := m.Store.SyncEmail(r.Context(), u.Key, id.Email, true); err != nil {
		m.logf("oidclient/rpuser: promote subject %s to verified: %v", id.Subject, err)
		backoff := interval
		if backoff < 0 {
			backoff = DefaultUnverifiedRecheck
		}
		m.retry.block(u.Key, now.Add(backoff), now)
		return given, givenID, u
	}
	// Re-read so User.Host is the host's row as it now stands, not the copy
	// fetched before the write.
	promoted, err := m.Store.LookupBySubject(r.Context(), id.Issuer, id.Subject)
	if err != nil {
		m.logf("oidclient/rpuser: re-read subject %s after promotion: %v", id.Subject, err)
		u.Email, u.EmailVerified = id.Email, true
		return claims, id, u
	}
	return claims, id, promoted
}

// retryPruneAt is the size at which retryLog sheds expired entries.
const retryPruneAt = 1024

// retryLog remembers, per user key, the time before which a failed promotion
// write is not attempted again. Entries exist only for users whose write
// failed and expire after one interval. It is per process.
type retryLog struct {
	mu    sync.Mutex
	until map[string]time.Time
}

func (l *retryLog) blocked(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	t, ok := l.until[key]
	return ok && now.Before(t)
}

func (l *retryLog) block(key string, until, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.until == nil {
		l.until = make(map[string]time.Time)
	}
	if len(l.until) >= retryPruneAt {
		for k, t := range l.until {
			if !now.Before(t) {
				delete(l.until, k)
			}
		}
	}
	l.until[key] = until
}

// clear forgets every backoff. For tests.
func (l *retryLog) clear() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.until = nil
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
