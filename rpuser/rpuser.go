// Package rpuser is the audited claims -> local-user path for relying parties
// built on oidclient: it turns the verified claims of a completed login into a
// provisioned row in the host's own users table, and resolves that row again on
// each request. Hosts keep their schema and queries; this package owns the
// policy. See https://github.com/infodancer/oidclient/issues/10.
//
// The policy, in full:
//
//   - Users are keyed strictly on (issuer, subject). Accounts are never matched
//     or merged by email: an upstream that recycles or reassigns an email must
//     not grant access to an existing local account.
//   - Mutable claims (email, email_verified) are synced at login, on the
//     existing row; a known subject never gets a second row. The display name
//     is set at creation and never overwritten -- hosts may let users edit it.
//   - The per-request path ([Middleware]) is read-only, with one exception: a
//     row stored as unverified is promoted when the provider says the address
//     is verified, and the session of such a user asks the provider again
//     every few minutes until it is. Verification normally lands just after
//     sign-up, on a session that would otherwise carry the old answer until
//     its next login. The exception is one-way and fires once per user;
//     nothing between logins lowers the flag or touches a verified row.
//   - Issuer comes from the host's client configuration, not a token claim:
//     oidclient validates the token's iss against the configured issuer during
//     verification, so the configured value is the authoritative string -- the
//     same one authz grants are keyed on.
//
// Authorization is out of scope by design: Identity carries no roles, and this
// package never reads role claims. Role resolution belongs to the host's
// authorization layer (see github.com/infodancer/authz).
package rpuser

import (
	"context"
	"errors"
	"fmt"

	"github.com/infodancer/oidclient"
)

// ErrNotFound is returned by [UserStore.LookupBySubject] when no user exists
// for an (issuer, subject) pair. Store implementations must map their driver's
// no-rows result to it.
var ErrNotFound = errors.New("oidclient/rpuser: user not found")

// Identity is the normalized, verified result of a completed login. It mirrors
// authz.Identity: (Issuer, Subject) is the stable key; DisplayName and Email
// are presentation data. It deliberately carries no roles -- authorization is
// resolved by the host against its own grant store, never from claims.
type Identity struct {
	Issuer        string
	Subject       string
	DisplayName   string
	Email         string
	EmailVerified bool
}

// FromClaims normalizes verified claims into an [Identity]. issuer is the
// client's configured issuer URL, which oidclient has already validated the
// token against. DisplayName falls back to the email address when the token
// carries no name claim -- the one place that policy lives.
func FromClaims(issuer string, c *oidclient.Claims) Identity {
	name := c.Name
	if name == "" {
		name = c.Email
	}
	return Identity{
		Issuer:        issuer,
		Subject:       c.Sub,
		DisplayName:   name,
		Email:         c.Email,
		EmailVerified: c.EmailVerified,
	}
}

// User is the store's view of a provisioned local user: the host's stable key
// plus the two mutable fields the sync policy compares. Host is an optional
// slot for the host's own user representation -- a store may set it in
// LookupBySubject and read it back from [UserFromContext], saving a second
// query per request; rpuser never inspects it.
type User struct {
	Key           string
	Email         string
	EmailVerified bool
	Host          any
}

// UserStore is implemented by the host over its own users table. The host owns
// the schema and the SQL; the methods are deliberately dumb so the provisioning
// policy stays in this package.
//
// The backing table must key users on (issuer, subject) -- typically a
// composite unique constraint -- so the store cannot violate the
// never-match-by-email rule even under a racing double-create.
type UserStore interface {
	// LookupBySubject returns the user for (issuer, subject), or [ErrNotFound].
	// It is called on every authenticated request -- twice on the one request
	// that promotes a row -- and must not write.
	LookupBySubject(ctx context.Context, issuer, subject string) (User, error)

	// SyncEmail persists a changed email / email_verified pair on an existing
	// row. It has two callers: [Provisioner.Provision] at login, when it
	// detects a change in either direction, and [Middleware.Optional] on an
	// ordinary request -- of any method, a GET included -- when it promotes an
	// unverified row to verified. The second caller only ever passes
	// verified=true, and normally once per user.
	//
	// Because it can run inside any request, keep it to the update itself: no
	// notifications, no work that assumes a login is in progress, nothing that
	// is expensive or unsafe to repeat. A failure is retried after
	// [Middleware.UnverifiedRecheck], so it must be idempotent.
	//
	// The stored flag mirrors the provider. A host that wants to mark an
	// address unverified on its own authority should keep that in a column of
	// its own: a value written here is overwritten by the provider's answer at
	// the next login, and an unverified one by the next promotion.
	SyncEmail(ctx context.Context, userKey, email string, verified bool) error

	// Create inserts a row for a first login, keyed on (id.Issuer, id.Subject),
	// and returns it. The identity is fully normalized (display-name fallback
	// applied) before Create is called.
	Create(ctx context.Context, id Identity) (User, error)
}

// Provisioner runs the login-time half of the policy: look the subject up,
// sync mutable claims on a hit, create on a miss.
type Provisioner struct {
	Store UserStore

	// Issuer is the client's configured issuer URL; it becomes Identity.Issuer
	// and half of the storage key.
	Issuer string

	// PreCreate, when set, runs on a first login after the lookup misses and
	// before Create. Returning handled=true short-circuits creation with the
	// returned user, reported as not-created -- the hook for host policies like
	// osg's seed-account adoption, where a placeholder row should be claimed
	// instead of a fresh one inserted. An error aborts the login.
	PreCreate func(ctx context.Context, id Identity) (User, bool, error)

	// Logf receives diagnostics for best-effort failures (a claim sync that did
	// not stick). Nil disables logging.
	Logf func(format string, args ...any)
}

func (p *Provisioner) logf(format string, args ...any) {
	if p.Logf != nil {
		p.Logf(format, args...)
	}
}

// Provision returns the local user for a completed login's claims, creating
// one on first login. created is true only for the fresh-Create path -- returning
// users and PreCreate adoptions report false -- so callers can route
// first-timers to onboarding.
//
// On a hit, changed mutable claims are synced best-effort: a failed sync is
// logged and the stored values returned, rather than failing the login.
func (p *Provisioner) Provision(ctx context.Context, claims *oidclient.Claims) (User, bool, error) {
	if claims == nil {
		return User{}, false, errors.New("oidclient/rpuser: nil claims")
	}
	return p.ProvisionIdentity(ctx, FromClaims(p.Issuer, claims))
}

// ProvisionIdentity is [Provisioner.Provision] over an already-normalized
// identity. It exists so the resource-server path -- which has an
// [oidclient.AccessToken] rather than claims -- runs the identical policy
// instead of a second copy of it. See accesstoken.go.
//
// id must be fully normalized, with the display-name fallback already applied;
// [FromClaims] and [FromAccessToken] both do that.
func (p *Provisioner) ProvisionIdentity(ctx context.Context, id Identity) (User, bool, error) {
	u, err := p.Store.LookupBySubject(ctx, id.Issuer, id.Subject)
	switch {
	case err == nil:
		email := u.Email
		if id.Email != "" {
			email = id.Email
		}
		if email != u.Email || id.EmailVerified != u.EmailVerified {
			if serr := p.Store.SyncEmail(ctx, u.Key, email, id.EmailVerified); serr != nil {
				p.logf("oidclient/rpuser: sync claims for subject %s: %v", id.Subject, serr)
			} else {
				u.Email = email
				u.EmailVerified = id.EmailVerified
			}
		}
		return u, false, nil
	case !errors.Is(err, ErrNotFound):
		return User{}, false, fmt.Errorf("oidclient/rpuser: lookup: %w", err)
	}

	if p.PreCreate != nil {
		adopted, handled, perr := p.PreCreate(ctx, id)
		if perr != nil {
			return User{}, false, fmt.Errorf("oidclient/rpuser: pre-create: %w", perr)
		}
		if handled {
			return adopted, false, nil
		}
	}

	created, err := p.Store.Create(ctx, id)
	if err != nil {
		return User{}, false, fmt.Errorf("oidclient/rpuser: create: %w", err)
	}
	return created, true, nil
}
