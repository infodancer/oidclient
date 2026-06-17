package session

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/infodancer/oidclient"
)

// memStore is an in-memory Store.
type memStore struct {
	mu   sync.Mutex
	rows map[string]Session
}

func newMemStore() *memStore { return &memStore{rows: map[string]Session{}} }

func (s *memStore) Create(_ context.Context, sess Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows[sess.ID] = sess
	return nil
}

func (s *memStore) Get(_ context.Context, id string) (Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.rows[id]; ok {
		return r, nil
	}
	return Session{}, ErrNotFound
}

func (s *memStore) Rotate(_ context.Context, id string, access, refresh []byte, accessExpiry time.Time, expectVersion int64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.rows[id]
	if !ok || r.Version != expectVersion {
		return false, nil
	}
	r.AccessToken = access
	r.RefreshToken = refresh
	r.AccessExpiry = accessExpiry
	r.Version = expectVersion + 1
	s.rows[id] = r
	return true, nil
}

func (s *memStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.rows, id)
	return nil
}

func (s *memStore) DeleteExpired(_ context.Context, cutoff time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	for id, r := range s.rows {
		if r.AbsoluteExpiry.Before(cutoff) {
			delete(s.rows, id)
			n++
		}
	}
	return n, nil
}

// fakeRenewer is a scriptable Renewer.
type fakeRenewer struct {
	validate func(token string) (*oidclient.Claims, error)
	refresh  func(token string) (*oidclient.Tokens, *oidclient.Claims, error)
	refreshN int
	mu       sync.Mutex
}

func (f *fakeRenewer) Validate(_ context.Context, token string) (*oidclient.Claims, error) {
	return f.validate(token)
}

func (f *fakeRenewer) Refresh(_ context.Context, token string) (*oidclient.Tokens, *oidclient.Claims, error) {
	f.mu.Lock()
	f.refreshN++
	f.mu.Unlock()
	return f.refresh(token)
}

func testKeyring(t *testing.T) *Keyring {
	t.Helper()
	kr := NewKeyring()
	if err := kr.Add("k1", key(1)); err != nil {
		t.Fatalf("keyring: %v", err)
	}
	return kr
}

func newManager(t *testing.T, store Store, ren Renewer, kr *Keyring) *Manager {
	t.Helper()
	m, err := New(Config{Store: store, Renewer: ren, Keyring: kr, CookieName: "sid"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m
}

// seed builds a Session with sealed tokens and stores it.
func seed(t *testing.T, store *memStore, kr *Keyring, id, at, rt string, accessExp, absExp time.Time, version int64) {
	t.Helper()
	a, err := kr.Seal([]byte(at), []byte(id))
	if err != nil {
		t.Fatal(err)
	}
	r, err := kr.Seal([]byte(rt), []byte(id))
	if err != nil {
		t.Fatal(err)
	}
	store.rows[id] = Session{
		ID: id, UserSub: "user-1",
		AccessToken: a, RefreshToken: r, Version: version,
		AccessExpiry: accessExp, AbsoluteExpiry: absExp,
	}
}

func reqCookie(id string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	if id != "" {
		r.AddCookie(&http.Cookie{Name: "sid", Value: id})
	}
	return r
}

func TestNew_RequiredConfig(t *testing.T) {
	kr := testKeyring(t)
	good := Config{Store: newMemStore(), Renewer: &fakeRenewer{}, Keyring: kr, CookieName: "sid"}
	if _, err := New(good); err != nil {
		t.Fatalf("valid config: %v", err)
	}
	mutate := map[string]func(*Config){
		"no store":    func(c *Config) { c.Store = nil },
		"no renewer":  func(c *Config) { c.Renewer = nil },
		"no keyring":  func(c *Config) { c.Keyring = nil },
		"no cookie":   func(c *Config) { c.CookieName = "" },
		"no live key": func(c *Config) { c.Keyring = NewKeyring() },
	}
	for name, mut := range mutate {
		t.Run(name, func(t *testing.T) {
			c := good
			mut(&c)
			if _, err := New(c); err == nil {
				t.Errorf("New(%s) = nil error, want a validation error", name)
			}
		})
	}
}

func TestNew_Defaults(t *testing.T) {
	m := newManager(t, newMemStore(), &fakeRenewer{}, testKeyring(t))
	if m.absoluteTTL != defaultAbsoluteTTL {
		t.Errorf("absoluteTTL = %v, want %v", m.absoluteTTL, defaultAbsoluteTTL)
	}
	if m.skew != defaultRefreshSkew {
		t.Errorf("skew = %v, want %v", m.skew, defaultRefreshSkew)
	}
}

func TestAuthenticate_NoOrUnknownCookie(t *testing.T) {
	m := newManager(t, newMemStore(), &fakeRenewer{}, testKeyring(t))
	if _, err := m.Authenticate(reqCookie("")); !errors.Is(err, ErrNoSession) {
		t.Errorf("no cookie: err = %v, want ErrNoSession", err)
	}
	if _, err := m.Authenticate(reqCookie("nope")); !errors.Is(err, ErrNoSession) {
		t.Errorf("unknown cookie: err = %v, want ErrNoSession", err)
	}
}

func TestAuthenticate_FastPath(t *testing.T) {
	store, kr := newMemStore(), testKeyring(t)
	seed(t, store, kr, "sid", "good-at", "rt-1", time.Now().Add(time.Hour), time.Now().Add(24*time.Hour), 0)
	ren := &fakeRenewer{
		validate: func(tok string) (*oidclient.Claims, error) {
			if tok != "good-at" {
				t.Errorf("validated %q, want good-at", tok)
			}
			return &oidclient.Claims{Sub: "user-1"}, nil
		},
		refresh: func(string) (*oidclient.Tokens, *oidclient.Claims, error) {
			t.Fatal("refresh must not run on the fast path")
			return nil, nil, nil
		},
	}
	m := newManager(t, store, ren, kr)
	claims, err := m.Authenticate(reqCookie("sid"))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if claims.Sub != "user-1" {
		t.Errorf("sub = %q, want user-1", claims.Sub)
	}
	if ren.refreshN != 0 {
		t.Errorf("refreshN = %d, want 0", ren.refreshN)
	}
}

func TestAuthenticate_RenewOnExpiredAccessToken(t *testing.T) {
	store, kr := newMemStore(), testKeyring(t)
	seed(t, store, kr, "sid", "stale-at", "rt-old", time.Now().Add(-time.Minute), time.Now().Add(24*time.Hour), 3)
	ren := &fakeRenewer{
		validate: func(string) (*oidclient.Claims, error) { return nil, errors.New("expired") },
		refresh: func(tok string) (*oidclient.Tokens, *oidclient.Claims, error) {
			if tok != "rt-old" {
				t.Errorf("refreshed with %q, want rt-old", tok)
			}
			return &oidclient.Tokens{AccessToken: "fresh-at", RefreshToken: "rt-new", Expiry: time.Now().Add(time.Hour)},
				&oidclient.Claims{Sub: "user-1"}, nil
		},
	}
	m := newManager(t, store, ren, kr)
	claims, err := m.Authenticate(reqCookie("sid"))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if claims.Sub != "user-1" {
		t.Errorf("sub = %q, want user-1", claims.Sub)
	}
	// Rotated tokens persisted (as ciphertext), version bumped, old rt discarded.
	got := store.rows["sid"]
	if got.Version != 4 {
		t.Errorf("version = %d, want 4 (bumped from 3)", got.Version)
	}
	at, err := kr.Open(got.AccessToken, []byte("sid"))
	if err != nil || string(at) != "fresh-at" {
		t.Errorf("stored access token = %q, %v; want fresh-at", at, err)
	}
	rt, err := kr.Open(got.RefreshToken, []byte("sid"))
	if err != nil || string(rt) != "rt-new" {
		t.Errorf("stored refresh token = %q, %v; want rt-new", rt, err)
	}
}

func TestAuthenticate_AbsoluteExpiryDeletesAndFails(t *testing.T) {
	store, kr := newMemStore(), testKeyring(t)
	seed(t, store, kr, "sid", "at", "rt", time.Now().Add(time.Hour), time.Now().Add(-time.Minute), 0)
	m := newManager(t, store, &fakeRenewer{}, kr)
	if _, err := m.Authenticate(reqCookie("sid")); !errors.Is(err, ErrNoSession) {
		t.Fatalf("err = %v, want ErrNoSession", err)
	}
	if _, ok := store.rows["sid"]; ok {
		t.Error("expired session row should have been deleted")
	}
}

func TestAuthenticate_RefreshFailureIsRealError(t *testing.T) {
	store, kr := newMemStore(), testKeyring(t)
	seed(t, store, kr, "sid", "stale-at", "rt-dead", time.Now().Add(-time.Minute), time.Now().Add(24*time.Hour), 0)
	ren := &fakeRenewer{
		validate: func(string) (*oidclient.Claims, error) { return nil, errors.New("expired") },
		refresh: func(string) (*oidclient.Tokens, *oidclient.Claims, error) {
			return nil, nil, errors.New("refresh token revoked")
		},
	}
	m := newManager(t, store, ren, kr)
	_, err := m.Authenticate(reqCookie("sid"))
	if err == nil {
		t.Fatal("want an error from a failed refresh")
	}
	if errors.Is(err, ErrNoSession) {
		t.Error("a failed refresh must be a real error, not ErrNoSession, so the host logs it")
	}
}

// On a lost rotation race (CAS miss), the manager adopts the winner's freshly
// stored access token instead of spending its own stale refresh token again.
func TestAuthenticate_CASLossAdoptsWinner(t *testing.T) {
	store, kr := newMemStore(), testKeyring(t)
	seed(t, store, kr, "sid", "stale-at", "rt-old", time.Now().Add(-time.Minute), time.Now().Add(24*time.Hour), 0)

	// Simulate the winner: before our Refresh result lands, another instance has
	// already rotated the row to version 1 with a valid access token.
	winnerAT, _ := kr.Seal([]byte("winner-at"), []byte("sid"))
	winnerRT, _ := kr.Seal([]byte("winner-rt"), []byte("sid"))

	ren := &fakeRenewer{
		validate: func(tok string) (*oidclient.Claims, error) {
			if tok == "winner-at" {
				return &oidclient.Claims{Sub: "user-1"}, nil
			}
			return nil, errors.New("stale")
		},
		refresh: func(string) (*oidclient.Tokens, *oidclient.Claims, error) {
			// Our grant succeeds, but the store has moved on under us: bump the row
			// so our CAS on version 0 misses.
			store.mu.Lock()
			r := store.rows["sid"]
			r.Version = 1
			r.AccessToken = winnerAT
			r.RefreshToken = winnerRT
			r.AccessExpiry = time.Now().Add(time.Hour)
			store.rows["sid"] = r
			store.mu.Unlock()
			return &oidclient.Tokens{AccessToken: "loser-at", RefreshToken: "loser-rt", Expiry: time.Now().Add(time.Hour)},
				&oidclient.Claims{Sub: "user-1"}, nil
		},
	}
	m := newManager(t, store, ren, kr)
	claims, err := m.Authenticate(reqCookie("sid"))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if claims.Sub != "user-1" {
		t.Errorf("sub = %q, want user-1", claims.Sub)
	}
	// The loser must not have overwritten the winner's tokens.
	got := store.rows["sid"]
	at, _ := kr.Open(got.AccessToken, []byte("sid"))
	if string(at) != "winner-at" {
		t.Errorf("stored access token = %q, want winner-at (loser must not overwrite)", at)
	}
}

func TestStartAndDestroy(t *testing.T) {
	store, kr := newMemStore(), testKeyring(t)
	m := newManager(t, store, &fakeRenewer{}, kr)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/callback", nil)
	tokens := &oidclient.Tokens{AccessToken: "at", RefreshToken: "rt", Expiry: time.Now().Add(time.Hour)}
	if err := m.Start(w, r, tokens, &oidclient.Claims{Sub: "user-9"}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if len(store.rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(store.rows))
	}
	var id string
	for k := range store.rows {
		id = k
	}
	// Tokens are stored encrypted, not plaintext.
	row := store.rows[id]
	if string(row.AccessToken) == "at" || string(row.RefreshToken) == "rt" {
		t.Error("tokens must be stored as ciphertext, not plaintext")
	}
	rt, err := kr.Open(row.RefreshToken, []byte(id))
	if err != nil || string(rt) != "rt" {
		t.Errorf("sealed refresh token did not round-trip: %q, %v", rt, err)
	}
	cookies := w.Result().Cookies()
	if len(cookies) == 0 || cookies[0].Value != id {
		t.Fatalf("cookie = %v, want session id %q", cookies, id)
	}

	w2, r2 := httptest.NewRecorder(), reqCookie(id)
	m.Destroy(w2, r2)
	if len(store.rows) != 0 {
		t.Errorf("Destroy left %d rows, want 0", len(store.rows))
	}
}

func TestSweep(t *testing.T) {
	store, kr := newMemStore(), testKeyring(t)
	seed(t, store, kr, "live", "at", "rt", time.Now().Add(time.Hour), time.Now().Add(time.Hour), 0)
	seed(t, store, kr, "dead", "at", "rt", time.Now().Add(time.Hour), time.Now().Add(-time.Hour), 0)
	m := newManager(t, store, &fakeRenewer{}, kr)
	n, err := m.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if n != 1 {
		t.Errorf("swept %d, want 1", n)
	}
	if _, ok := store.rows["dead"]; ok {
		t.Error("expired row should be gone")
	}
	if _, ok := store.rows["live"]; !ok {
		t.Error("live row should remain")
	}
}
