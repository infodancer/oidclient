// Package session provides server-side OIDC sessions for relying parties built
// on oidclient: the browser holds an opaque session id in a cookie, while the
// access token and the rotating refresh token live server-side, encrypted at
// rest. The Manager validates and renews the access token on each request
// (renewal collapsed under concurrency and guarded against the refresh-token
// replay race), and revokes sessions on logout.
//
// The package persists nothing itself: the host application supplies a Store
// implemented over its own database, and a Keyring for the at-rest encryption.
// See docs/session-design.md in this repository for the rationale.
package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/infodancer/oidclient"
	"golang.org/x/sync/singleflight"
)

const (
	defaultAbsoluteTTL = 30 * 24 * time.Hour
	defaultRefreshSkew = 60 * time.Second
	refreshTimeout     = 10 * time.Second
)

// ErrNoSession means the request carried no usable session: no cookie, an
// unknown id, or a session past its absolute TTL. Callers treat it as the
// expected unauthenticated case (proceed anonymous, or redirect to login),
// distinct from a real fault such as a failed renewal or a store error, which
// should be logged.
var ErrNoSession = errors.New("oidclient/session: no session")

// ErrNotFound is what a Store.Get returns when no row matches the id. The
// Manager maps it to ErrNoSession.
var ErrNotFound = errors.New("oidclient/session: not found")

// Session is the persisted state the Manager needs. The token fields cross the
// Store boundary as ciphertext: the Manager seals them before Create and Rotate
// and opens them after Get, so a Store implementation never handles plaintext
// tokens.
type Session struct {
	ID             string // opaque session id; the cookie value
	UserSub        string // claims.Sub, for the host's user lookup
	AccessToken    []byte // AES-GCM ciphertext
	RefreshToken   []byte // AES-GCM ciphertext
	Version        int64  // compare-and-swap guard for rotation
	AccessExpiry   time.Time
	AbsoluteExpiry time.Time
}

// Store is the host-implemented persistence boundary. Implementations own the
// schema and driver; the Manager owns the values. All token bytes passed in and
// out are ciphertext.
type Store interface {
	Create(ctx context.Context, s Session) error
	// Get returns ErrNotFound when no row matches id.
	Get(ctx context.Context, id string) (Session, error)
	// Rotate compare-and-swaps on version: it writes the new ciphertext, expiry,
	// and version=expectVersion+1 only if the row's current version still equals
	// expectVersion. It returns true on success, false on a CAS miss (another
	// writer rotated first).
	Rotate(ctx context.Context, id string, access, refresh []byte, accessExpiry time.Time, expectVersion int64) (bool, error)
	Delete(ctx context.Context, id string) error
	DeleteExpired(ctx context.Context, cutoff time.Time) (int64, error)
}

// Renewer is the slice of *oidclient.Client the Manager needs: validate a stored
// access token and spend a refresh token. The concrete client satisfies it;
// tests substitute a fake.
type Renewer interface {
	Validate(ctx context.Context, accessToken string) (*oidclient.Claims, error)
	Refresh(ctx context.Context, refreshToken string) (*oidclient.Tokens, *oidclient.Claims, error)
}

// The concrete client is the production Renewer.
var _ Renewer = (*oidclient.Client)(nil)

// Config builds a Manager. Store, Renewer, Keyring, and CookieName are required.
type Config struct {
	Store      Store
	Renewer    Renewer
	Keyring    *Keyring
	CookieName string

	// AbsoluteTTL is the hard session lifetime regardless of renewal. It must
	// stay under the IdP's refresh-token lifetime, or renewal would fail before
	// the session expires. Zero uses the 30d default.
	AbsoluteTTL time.Duration

	// RefreshSkew renews the access token this long before it actually expires,
	// so a request never races the expiry boundary. Zero uses the 60s default.
	RefreshSkew time.Duration
}

// Manager owns the server-side session lifecycle.
type Manager struct {
	store       Store
	renewer     Renewer
	keyring     *Keyring
	cookie      string
	absoluteTTL time.Duration
	skew        time.Duration

	// group collapses concurrent renewals of the same session into one
	// refresh-token grant. webauth rotates the refresh token on every use with
	// replay detection, so two parallel requests must never both spend it.
	group singleflight.Group
}

// New validates cfg and constructs a Manager.
func New(cfg Config) (*Manager, error) {
	if cfg.Store == nil {
		return nil, errors.New("oidclient/session: Config.Store is required")
	}
	if cfg.Renewer == nil {
		return nil, errors.New("oidclient/session: Config.Renewer is required")
	}
	if cfg.Keyring == nil {
		return nil, errors.New("oidclient/session: Config.Keyring is required")
	}
	if cfg.Keyring.ActiveID() == "" {
		return nil, errors.New("oidclient/session: Config.Keyring has no active key")
	}
	if cfg.CookieName == "" {
		return nil, errors.New("oidclient/session: Config.CookieName is required")
	}
	m := &Manager{
		store:       cfg.Store,
		renewer:     cfg.Renewer,
		keyring:     cfg.Keyring,
		cookie:      cfg.CookieName,
		absoluteTTL: cfg.AbsoluteTTL,
		skew:        cfg.RefreshSkew,
	}
	if m.absoluteTTL <= 0 {
		m.absoluteTTL = defaultAbsoluteTTL
	}
	if m.skew <= 0 {
		m.skew = defaultRefreshSkew
	}
	return m, nil
}

// newID returns a 256-bit opaque, URL-safe session identifier.
func newID() (string, error) {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("oidclient/session: generate id: %w", err)
	}
	return hex.EncodeToString(buf[:]), nil
}

// Start persists a freshly exchanged token set as a new session and writes the
// opaque session-id cookie. Call it from the OIDC callback after Exchange.
func (m *Manager) Start(w http.ResponseWriter, r *http.Request, tokens *oidclient.Tokens, claims *oidclient.Claims) error {
	id, err := newID()
	if err != nil {
		return err
	}
	access, refresh, err := m.sealTokens(id, tokens)
	if err != nil {
		return err
	}
	if err := m.store.Create(r.Context(), Session{
		ID:             id,
		UserSub:        claims.Sub,
		AccessToken:    access,
		RefreshToken:   refresh,
		Version:        0,
		AccessExpiry:   tokens.Expiry,
		AbsoluteExpiry: time.Now().Add(m.absoluteTTL),
	}); err != nil {
		return fmt.Errorf("oidclient/session: create: %w", err)
	}
	oidclient.SetSessionCookie(w, m.cookie, id, oidclient.IsSecure(r))
	return nil
}

// Authenticate resolves the request's session cookie to validated claims,
// renewing the access token when it is absent or near expiry. It returns
// ErrNoSession when there is no usable session.
func (m *Manager) Authenticate(r *http.Request) (*oidclient.Claims, error) {
	c, err := r.Cookie(m.cookie)
	if err != nil || c.Value == "" {
		return nil, ErrNoSession
	}
	sess, err := m.store.Get(r.Context(), c.Value)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrNoSession
	}
	if err != nil {
		return nil, err
	}
	// A session past its hard TTL is dead even if the tokens would still verify.
	if time.Now().After(sess.AbsoluteExpiry) {
		_ = m.store.Delete(r.Context(), sess.ID)
		return nil, ErrNoSession
	}

	// Fast path: the stored access token is comfortably in-date -- decrypt and
	// validate its signature (cheap; JWKS is cached) without touching the IdP.
	if claims, ok := m.tryStoredAccessToken(r.Context(), sess); ok {
		return claims, nil
	}
	return m.renew(sess)
}

// renew performs (or joins) a single refresh-token grant for the session and
// persists the rotated tokens. Concurrent callers for the same session id share
// one grant via singleflight; the loser of a cross-instance race re-reads the
// winner's tokens rather than spending its own stale refresh token.
func (m *Manager) renew(sess Session) (*oidclient.Claims, error) {
	v, err, _ := m.group.Do(sess.ID, func() (any, error) {
		// Detached, timeout-bounded context: a client disconnect must not cancel
		// a refresh that other in-flight requests are waiting on.
		ctx, cancel := context.WithTimeout(context.Background(), refreshTimeout)
		defer cancel()

		// Re-read inside the critical section: another goroutine in this process
		// may have refreshed while we waited on the singleflight barrier.
		cur, err := m.store.Get(ctx, sess.ID)
		if errors.Is(err, ErrNotFound) {
			return nil, ErrNoSession
		}
		if err != nil {
			return nil, err
		}
		if claims, ok := m.tryStoredAccessToken(ctx, cur); ok {
			return claims, nil
		}

		refresh, err := m.keyring.Open(cur.RefreshToken, []byte(cur.ID))
		if err != nil {
			return nil, fmt.Errorf("oidclient/session: decrypt refresh token: %w", err)
		}
		tokens, claims, err := m.renewer.Refresh(ctx, string(refresh))
		if err != nil {
			return nil, fmt.Errorf("oidclient/session: refresh: %w", err)
		}
		access, sealedRefresh, err := m.sealTokens(cur.ID, tokens)
		if err != nil {
			return nil, err
		}
		// Persist under a CAS on the version we read. Losing means another
		// instance refreshed first; adopt its tokens instead of overwriting.
		ok, err := m.store.Rotate(ctx, cur.ID, access, sealedRefresh, tokens.Expiry, cur.Version)
		if err != nil {
			return nil, err
		}
		if !ok {
			latest, err := m.store.Get(ctx, cur.ID)
			if err != nil {
				return nil, err
			}
			if claims, ok := m.tryStoredAccessToken(ctx, latest); ok {
				return claims, nil
			}
			return nil, errors.New("oidclient/session: lost rotation race and the winner's token did not validate")
		}
		return claims, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*oidclient.Claims), nil
}

// tryStoredAccessToken decrypts and validates the session's stored access token
// when it is comfortably in-date, returning its claims. It reports ok=false when
// the token is near expiry, fails to decrypt, or no longer verifies -- all of
// which mean the caller should fall through to a refresh.
func (m *Manager) tryStoredAccessToken(ctx context.Context, sess Session) (*oidclient.Claims, bool) {
	if !time.Now().Before(sess.AccessExpiry.Add(-m.skew)) {
		return nil, false
	}
	at, err := m.keyring.Open(sess.AccessToken, []byte(sess.ID))
	if err != nil {
		return nil, false
	}
	claims, err := m.renewer.Validate(ctx, string(at))
	if err != nil {
		return nil, false
	}
	return claims, true
}

// sealTokens encrypts an access/refresh token pair under the session id.
func (m *Manager) sealTokens(id string, tokens *oidclient.Tokens) (access, refresh []byte, err error) {
	access, err = m.keyring.Seal([]byte(tokens.AccessToken), []byte(id))
	if err != nil {
		return nil, nil, fmt.Errorf("oidclient/session: seal access token: %w", err)
	}
	refresh, err = m.keyring.Seal([]byte(tokens.RefreshToken), []byte(id))
	if err != nil {
		return nil, nil, fmt.Errorf("oidclient/session: seal refresh token: %w", err)
	}
	return access, refresh, nil
}

// Destroy revokes the request's session (logout): it deletes the server-side
// row so the session is dead immediately, and expires the cookie. The refresh
// token is discarded with the row; it expires at the IdP on its own TTL.
func (m *Manager) Destroy(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(m.cookie); err == nil && c.Value != "" {
		_ = m.store.Delete(r.Context(), c.Value)
	}
	oidclient.ClearSessionCookie(w, m.cookie, oidclient.IsSecure(r))
}

// Sweep deletes sessions past their absolute TTL. Expired rows are also rejected
// at request time (Authenticate checks AbsoluteExpiry); this just keeps the
// table from growing. Run it on an interval.
func (m *Manager) Sweep(ctx context.Context) (int64, error) {
	return m.store.DeleteExpired(ctx, time.Now())
}
