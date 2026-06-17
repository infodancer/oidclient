# Design: `oidclient/session` -- server-side OIDC sessions

Status: proposal. Author: Matthew Hunter. Target: a new `session` subpackage
under `github.com/infodancer/oidclient`.

## Motivation

Three apps -- herald, speculativefiction (sf), and osg -- authenticate as OIDC
relying parties against webauth via this library. Each one needs to hold a
*session* after login. Today they diverge:

- **herald** writes the access token + rotating refresh token to a server-side
  store and renews on each request (singleflight-collapsed, CAS-guarded against
  the refresh-token replay race). Mature, but bespoke and copied by hand.
- **sf** just grew the same thing, lifted from herald's implementation -- a
  second hand-rolled copy of the tricky concurrency logic.
- **osg** still does the old thing: the session *is* the access-token JWT in the
  cookie, with no refresh. At the access-token TTL (24h on the webauth tenants)
  the user is silently treated as anonymous and any auth-gated action dead-ends
  at a bare 401. This is a latent bug, not yet reported.

The library already exposes the renewal primitives (`Exchange`, `Refresh`,
`Claims.ExpiresAt`) and tells callers to "keep the refresh token server-side."
What it does not provide is the *session lifecycle* that wraps those primitives:
storing the tokens, renewing under concurrency, rotating safely, and revoking on
logout. So every app reinvents it, and the rotation race -- the one piece most
likely to be wrong -- gets written more than once.

Separately, none of the three encrypts the stored refresh token at rest. The
refresh token is a long-lived bearer credential (the webauth tenants set
`refresh_ttl_sec=604800`, 7d), and the RP holds the *only replayable copy*:
webauth stores just a hash of it. That is worth protecting against the common
DB-only exposure path (leaked backup, disk snapshot, read replica, a SQLi
`SELECT`).

This package consolidates the lifecycle and the encryption once, tested once,
and lets osg adopt it instead of growing a third copy.

## Goals

- One tested implementation of the session lifecycle: start, authenticate,
  renew (singleflight + compare-and-swap on rotation), destroy, sweep.
- Encryption of token material at rest, transparent to the app.
- Storage-agnostic: each app keeps its own database, schema, and driver.
- No new top-level dependency for any of the three apps.

## Non-goals

- Owning a database connection, schema, or migration. The app does that.
- A login UI, route mounting, or middleware. The package returns claims; the app
  decides what to do with an unauthenticated request (sf, for instance, bounces
  gated routes to login and leaves public pages open).
- Key management infrastructure. The app supplies a key; the package uses it.

## Placement: a subpackage, not a new module

The package goes under `oidclient` rather than in `infodancer/web` or a fresh
`infodancer/authsession`, for one concrete reason: **`oidclient` is the only
dependency all three apps already share.** sf and osg pull many
`infodancer/web/*` modules; herald deliberately depends on `oidclient` alone.
Putting the session code anywhere else forces a new module dependency on at
least one app (herald, the lean one). A subpackage adds nothing new to anyone's
`go.mod`.

The core `oidclient` package stays stateless -- it gains no storage or crypto
concern. Callers who only want the protocol client import `oidclient` and never
see `session`. Callers who want managed sessions opt in by importing
`oidclient/session`. The subpackage depends on the core (`Exchange`, `Refresh`,
`Validate`, the cookie helpers), not the other way around, so there is no import
cycle and no scope creep in the core.

## Where the data lives

The package persists nothing. It defines a `Store` interface; the actual rows
live in **each app's own database, in an app-owned table**, reached through a
thin adapter the app writes. The package's only persistent-looking state is the
in-memory `singleflight.Group`.

```
caller (app HTTP layer)
  -> session.Manager        (lifecycle + crypto, in this package)
       -> Store interface   (implemented by the app over its DB)
            -> app's sessions table
```

So sf wraps its sqlc `Queries`, herald points its existing sessions table at the
adapter, osg adds a table plus adapter. The schema and driver are the app's;
the orchestration and crypto are the library's.

## Encryption boundary

The `Manager` encrypts and decrypts token fields **at the `Store` boundary**, so
a `Store` only ever receives ciphertext and no app can accidentally persist a
plaintext token. The app's token columns hold opaque bytes.

- **Cipher**: AES-256-GCM (stdlib `crypto/aes` + `cipher.NewGCM`). Random 96-bit
  nonce per encryption; the stored blob is `keyID || nonce || ciphertext||tag`.
- **AAD**: the session id, so a ciphertext cannot be transplanted into another
  row.
- **Keyring**: a small `Keyring` type with explicit `Add(id, key)` and
  `SetActive(id)`, so the app states which key encrypts and which remain
  available to decrypt. The active key encrypts; any key in the ring can decrypt.
  A `keyID` prefix on each blob lets a key roll forward -- new writes use the new
  key, old rows decrypt under the old one and re-encrypt on their next rotation.
  No big-bang re-encryption.
- **What gets encrypted**: both the refresh token and the access token. The
  access token is a short-lived signed JWT and less sensitive, but encrypting it
  under the same envelope costs nothing and keeps the columns uniform.
- **Key source**: the app loads the key(s) from its own secret store and passes
  them in config. The key never touches the database. The package does not read
  env vars or files.

### Rotation CAS becomes a version counter

herald's current compare-and-swap rotates `... WHERE refresh_token = <spent
token>`, comparing on the token value. That stops working once the token column
holds ciphertext, because GCM with a per-write random nonce produces different
ciphertext every time -- there is nothing stable to compare.

So the rotation guard moves from the token value to a **monotonic `version`
counter** on the row:

```
Rotate(... WHERE id = $id AND version = $expected)   -- sets version = $expected + 1
```

The manager reads `Session.Version`, computes the refresh, and rotates under the
version it read. A zero-row result means another instance (or goroutine) rotated
first; the loser re-reads the row and adopts the winner's tokens rather than
spending its own now-stale refresh token. Same replay-race protection as before,
with no token-derived comparison. (webauth stores a *hash* of the refresh token
for the same "can't keep the plaintext" reason.)

## Public API (sketch)

```go
package session

// Session is the persisted state the manager needs. The token fields cross the
// Store boundary as ciphertext: the manager encrypts before Create/Rotate and
// decrypts after Get, so a Store implementation never handles plaintext tokens.
type Session struct {
    ID             string    // opaque session id; the cookie value
    UserSub        string    // claims.Sub, for app-side user lookup
    AccessToken    []byte    // AES-GCM ciphertext
    RefreshToken   []byte    // AES-GCM ciphertext
    Version        int64     // CAS guard for rotation
    AccessExpiry   time.Time
    AbsoluteExpiry time.Time
}

// ErrNotFound is returned by Store.Get when no row matches the id.
var ErrNotFound = errors.New("oidclient/session: not found")

// Store is the app-implemented persistence boundary. Implementations own the
// schema and driver; the manager owns the values.
type Store interface {
    Create(ctx context.Context, s Session) error
    Get(ctx context.Context, id string) (Session, error) // ErrNotFound when absent
    // Rotate compare-and-swaps on version: it applies the new ciphertext and
    // bumps the version only if the row's current version equals expectVersion.
    // Returns true on success, false on a CAS miss (someone rotated first).
    Rotate(ctx context.Context, id string, access, refresh []byte, accessExpiry time.Time, expectVersion int64) (bool, error)
    Delete(ctx context.Context, id string) error
    DeleteExpired(ctx context.Context, cutoff time.Time) (int64, error)
}

// Renewer is the slice of *oidclient.Client the manager needs: validate a
// stored access token and spend a refresh token. The concrete client satisfies
// it; tests substitute a fake.
type Renewer interface {
    Validate(ctx context.Context, accessToken string) (*oidclient.Claims, error)
    Refresh(ctx context.Context, refreshToken string) (*oidclient.Tokens, *oidclient.Claims, error)
}

type Config struct {
    Store       Store
    Renewer     Renewer
    Keyring     *Keyring      // token-at-rest encryption; required
    CookieName  string        // session-id cookie name
    AbsoluteTTL time.Duration // hard session lifetime; default 30d; must stay under the IdP refresh-token TTL
    RefreshSkew time.Duration // renew this long before access-token expiry (default 60s)
}

type Manager struct { /* ... */ }

func New(cfg Config) (*Manager, error)

// Start exchanges a freshly issued token set into a new stored session and
// writes the opaque session-id cookie. Called from the OIDC callback.
func (m *Manager) Start(w http.ResponseWriter, r *http.Request, tokens *oidclient.Tokens, claims *oidclient.Claims) error

// Authenticate resolves the request's session cookie to validated claims,
// renewing the access token when it is absent or near expiry. Returns
// ErrNoSession when there is no usable session.
func (m *Manager) Authenticate(r *http.Request) (*oidclient.Claims, error)

// Destroy revokes the request's session (logout) and clears the cookie.
func (m *Manager) Destroy(w http.ResponseWriter, r *http.Request)

// Sweep deletes sessions past their absolute TTL; run on an interval.
func (m *Manager) Sweep(ctx context.Context) (int64, error)
```

`ErrNoSession` stays exported so callers can distinguish the expected
unauthenticated case (proceed anonymous / redirect to login) from a real fault
(a failed renewal, a transient store error) that should be logged -- the gap
that hid the original sf bug.

## Reference schema (app-owned)

Postgres shown; herald's SQLite variant is the obvious analogue.

```
id              text        primary key   -- opaque session id (the cookie)
user_sub        text        not null
access_token    bytea       not null      -- AES-GCM ciphertext
refresh_token   bytea       not null      -- AES-GCM ciphertext
version         bigint      not null default 0
access_expiry   timestamptz not null
absolute_expiry timestamptz not null
created_at      timestamptz not null default now()
updated_at      timestamptz not null default now()
```

Index `absolute_expiry` for the sweep and `user_sub` if the app ever lists a
user's sessions.

## Concurrency

Unchanged from herald's proven approach, now in one place:

- `singleflight` collapses concurrent renewals of the same session id into a
  single refresh-token grant, so two in-flight requests never both spend the
  rotating token.
- The renewal runs on a detached, timeout-bounded context so a client
  disconnect does not cancel a refresh shared by other requests.
- The CAS (now on `version`) handles the cross-process race: only one writer
  lands the rotation; the loser re-reads and adopts.

## Migration and sequencing

osg is the forcing function: it needs a session built regardless, so build it
shared rather than copy herald a third time.

1. **Build `oidclient/session`** -- lift herald's manager, add the `Store`
   interface, add the keyring/encryption, switch the CAS to a version counter.
   Test the rotation race and the crypto here, once.
2. **Migrate sf** -- it has fresh tests from the inline implementation to
   validate the swap against; lowest risk. Add the `version` column and the
   ciphertext columns; write the sqlc `Store` adapter.
3. **Migrate herald** -- replace its bespoke `session.go` with a `Store` adapter
   over its existing table (add `version`, convert token columns to ciphertext).
4. **osg** -- bump `oidclient` v0.3.1 -> current, add the table + adapter, mount
   the manager. Gets the renewal fix and encryption together.

Steps 2 and 3 refactor working code, so each is gated behind its own suite; the
payoff is osg-for-cheap plus a single tested copy of the race and crypto logic.

## Rollout

Adopting the opaque-id cookie logs existing users out once -- their old
cookie (a JWT for osg, an opaque id under a now-changed scheme for sf/herald)
no longer resolves to a row, so they re-login transparently on the next gated
action. Acceptable, one-time, per app at its deploy.

The keyring is required: an app configured for OIDC but missing a session key
should fail closed at startup rather than silently storing plaintext. A local or
test deployment can supply a throwaway key explicitly.

## Testing

- In the package: the manager lifecycle against an in-memory `Store` and a fake
  `Renewer` (fast path, renew-on-expiry, absolute-expiry deletion, refresh
  failure is a real error not `ErrNoSession`, CAS-miss adopts the winner); the
  keyring round-trips, rejects a wrong key, honors AAD (a blob from one id fails
  to decrypt under another), and rolls key ids.
- In each app: a thin `Store` adapter test against its real driver, plus the
  existing higher-level auth tests.

## Decisions

1. **Keyring shape** -- a small `Keyring` type with explicit `Add(id, key)` and
   `SetActive(id)`, so key rotation is an explicit operation rather than a
   convention over a bare map.
2. **Encrypt the access token too** -- yes. Both token columns are encrypted
   under the same envelope; the access token being short-lived does not justify a
   split storage path.
3. **AbsoluteTTL default** -- 30d, overridable. There is no data-handling
   requirement driving a short idle timeout, so the default favors not logging
   active users out weekly; an app with stricter needs sets its own, bounded
   under the IdP refresh-token TTL.
