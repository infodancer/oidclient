package rpuser

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/infodancer/oidclient"
	"github.com/infodancer/oidclient/session"
)

// fakeAuthenticator stands in for *session.Manager.
type fakeAuthenticator struct {
	claims *oidclient.Claims
	err    error
}

func (f *fakeAuthenticator) Authenticate(_ *http.Request) (*oidclient.Claims, error) {
	return f.claims, f.err
}

// hostRow is a stand-in for a host's own user type, carried through User.Host.
type hostRow struct{ ID int64 }

// serveMW runs one request through m.Optional and returns what the inner
// handler saw in its context.
func serveMW(t *testing.T, m *Middleware) (id *Identity, u *User, claims *oidclient.Claims) {
	t.Helper()
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id = IdentityFromContext(r.Context())
		u = UserFromContext(r.Context())
		claims = ClaimsFromContext(r.Context())
	})
	rec := httptest.NewRecorder()
	m.Optional(inner).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("middleware wrote status %d, want pass-through 200", rec.Code)
	}
	return id, u, claims
}

func TestMiddleware_NoSessionIsAnonymous(t *testing.T) {
	var logged []string
	m := &Middleware{
		Authenticator: &fakeAuthenticator{err: session.ErrNoSession},
		Store:         newFakeStore(),
		Issuer:        testIssuer,
		Logf:          func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) },
	}
	id, u, claims := serveMW(t, m)
	if id != nil || u != nil || claims != nil {
		t.Errorf("anonymous request leaked context values: id=%v u=%v claims=%v", id, u, claims)
	}
	// ErrNoSession is the expected anonymous case, not a fault worth logging.
	if len(logged) != 0 {
		t.Errorf("ErrNoSession was logged: %v", logged)
	}
}

func TestMiddleware_AuthenticatedPopulatesContext(t *testing.T) {
	st := newFakeStore()
	st.put(testIssuer, "sub-1", User{Key: "u1", Email: "a@example.com", EmailVerified: true, Host: &hostRow{ID: 42}})
	m := &Middleware{
		Authenticator: &fakeAuthenticator{claims: &oidclient.Claims{Sub: "sub-1", Email: "a@example.com", EmailVerified: true, Name: "Alice"}},
		Store:         st,
		Issuer:        testIssuer,
	}
	id, u, claims := serveMW(t, m)
	if id == nil || u == nil || claims == nil {
		t.Fatalf("authenticated request missing context values: id=%v u=%v claims=%v", id, u, claims)
	}
	if id.Issuer != testIssuer || id.Subject != "sub-1" {
		t.Errorf("identity = %+v, want issuer/subject populated", id)
	}
	if u.Key != "u1" {
		t.Errorf("user key = %q, want u1", u.Key)
	}
	// The host's own row rides through untouched.
	row, ok := u.Host.(*hostRow)
	if !ok || row.ID != 42 {
		t.Errorf("user Host = %#v, want the host row carried through", u.Host)
	}
	if claims.Sub != "sub-1" {
		t.Errorf("claims sub = %q, want sub-1", claims.Sub)
	}
}

func TestMiddleware_UnknownSubjectIsAnonymous(t *testing.T) {
	var logged []string
	m := &Middleware{
		Authenticator: &fakeAuthenticator{claims: &oidclient.Claims{Sub: "sub-ghost"}},
		Store:         newFakeStore(), // no users
		Issuer:        testIssuer,
		Logf:          func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) },
	}
	id, u, _ := serveMW(t, m)
	if id != nil || u != nil {
		t.Error("unknown subject leaked identity/user into context")
	}
	// A live session with no user row is anomalous and must be diagnosable.
	if len(logged) == 0 {
		t.Error("unknown subject was not logged")
	}
}

func TestMiddleware_AuthErrorLoggedAndAnonymous(t *testing.T) {
	var logged []string
	m := &Middleware{
		Authenticator: &fakeAuthenticator{err: errors.New("store down")},
		Store:         newFakeStore(),
		Issuer:        testIssuer,
		Logf:          func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) },
	}
	id, u, _ := serveMW(t, m)
	if id != nil || u != nil {
		t.Error("failed authentication leaked context values")
	}
	if len(logged) == 0 {
		t.Error("authentication fault was not logged")
	}
}

func TestMiddleware_NilAuthenticatorIsAnonymous(t *testing.T) {
	m := &Middleware{Store: newFakeStore(), Issuer: testIssuer}
	id, u, claims := serveMW(t, m)
	if id != nil || u != nil || claims != nil {
		t.Error("nil authenticator leaked context values")
	}
}

// The per-request path stays read-only for a verified row, whatever the
// session's claims say: mutable claims on a verified row sync at login only.
func TestMiddleware_VerifiedRowIsReadOnly(t *testing.T) {
	st := newFakeStore()
	st.put(testIssuer, "sub-1", User{Key: "u1", Email: "old@example.com", EmailVerified: true})
	auth := &fakeRechecker{fakeAuthenticator: fakeAuthenticator{claims: &oidclient.Claims{Sub: "sub-1", Email: "new@example.com", EmailVerified: false}}}
	m := &Middleware{Authenticator: auth, Store: st, Issuer: testIssuer}
	_, u, _ := serveMW(t, m)
	if len(st.syncCalls) != 0 || len(st.createCalls) != 0 {
		t.Errorf("per-request path wrote to a verified row: syncs=%d creates=%d", len(st.syncCalls), len(st.createCalls))
	}
	if auth.rechecks != 0 {
		t.Errorf("a verified user's session was rechecked %d times, want 0", auth.rechecks)
	}
	if !u.EmailVerified || u.Email != "old@example.com" {
		t.Errorf("user = %+v, want the stored row untouched", u)
	}
}

// fakeRechecker is a fakeAuthenticator that can also renew early. rechecked,
// when set, is what the provider would say now.
type fakeRechecker struct {
	fakeAuthenticator
	rechecked  *oidclient.Claims
	recheckErr error
	rechecks   int
	interval   time.Duration
}

func (f *fakeRechecker) Recheck(_ *http.Request, minInterval time.Duration) (*oidclient.Claims, error) {
	f.rechecks++
	f.interval = minInterval
	if f.recheckErr != nil {
		return nil, f.recheckErr
	}
	if f.rechecked != nil {
		return f.rechecked, nil
	}
	return f.claims, nil
}

// An address verified at the provider after sign-in: the stored row says
// unverified, the session's claims are from before, and only asking the
// provider again shows the change. The row is promoted and this same request
// already sees a verified user, with the host's row re-read.
func TestMiddleware_UnverifiedRowIsRecheckedAndPromoted(t *testing.T) {
	st := newFakeStore()
	st.put(testIssuer, "sub-1", User{Key: "u1", Email: "a@example.com", EmailVerified: false})
	auth := &fakeRechecker{
		fakeAuthenticator: fakeAuthenticator{claims: &oidclient.Claims{Sub: "sub-1", Email: "a@example.com"}},
		rechecked:         &oidclient.Claims{Sub: "sub-1", Email: "a@example.com", EmailVerified: true},
	}
	m := &Middleware{Authenticator: auth, Store: st, Issuer: testIssuer}

	id, u, claims := serveMW(t, m)
	if auth.rechecks != 1 {
		t.Fatalf("rechecks = %d, want 1", auth.rechecks)
	}
	if auth.interval != DefaultUnverifiedRecheck {
		t.Errorf("recheck interval = %v, want the default %v", auth.interval, DefaultUnverifiedRecheck)
	}
	if len(st.syncCalls) != 1 || st.syncCalls[0] != (syncCall{key: "u1", email: "a@example.com", verified: true}) {
		t.Fatalf("syncs = %+v, want one promotion of u1", st.syncCalls)
	}
	if !u.EmailVerified || !id.EmailVerified || !claims.EmailVerified {
		t.Errorf("request context still unverified: user=%v identity=%v claims=%v", u.EmailVerified, id.EmailVerified, claims.EmailVerified)
	}
}

// Claims that already say verified need no trip to the provider.
func TestMiddleware_VerifiedClaimsPromoteWithoutRecheck(t *testing.T) {
	st := newFakeStore()
	st.put(testIssuer, "sub-1", User{Key: "u1", Email: "old@example.com", EmailVerified: false})
	auth := &fakeRechecker{fakeAuthenticator: fakeAuthenticator{claims: &oidclient.Claims{Sub: "sub-1", Email: "new@example.com", EmailVerified: true}}}
	m := &Middleware{Authenticator: auth, Store: st, Issuer: testIssuer}

	_, u, _ := serveMW(t, m)
	if auth.rechecks != 0 {
		t.Errorf("rechecks = %d, want 0", auth.rechecks)
	}
	// The verified flag describes the address in the claims, so the two are
	// written together, exactly as a sign-in would.
	if len(st.syncCalls) != 1 || st.syncCalls[0] != (syncCall{key: "u1", email: "new@example.com", verified: true}) {
		t.Fatalf("syncs = %+v, want one promotion carrying the claims' address", st.syncCalls)
	}
	if !u.EmailVerified || u.Email != "new@example.com" {
		t.Errorf("user = %+v, want promoted", u)
	}
}

// Still unverified at the provider: nothing is written, however often it is
// asked.
func TestMiddleware_StillUnverifiedWritesNothing(t *testing.T) {
	st := newFakeStore()
	st.put(testIssuer, "sub-1", User{Key: "u1", Email: "a@example.com"})
	auth := &fakeRechecker{fakeAuthenticator: fakeAuthenticator{claims: &oidclient.Claims{Sub: "sub-1", Email: "a@example.com"}}}
	m := &Middleware{Authenticator: auth, Store: st, Issuer: testIssuer}
	_, u, _ := serveMW(t, m)
	if len(st.syncCalls) != 0 {
		t.Errorf("syncs = %+v, want none", st.syncCalls)
	}
	if u == nil || u.EmailVerified {
		t.Errorf("user = %+v, want present and unverified", u)
	}
}

// Promotion only ever raises the flag. No claim can lower it here.
func TestMiddleware_NeverDemotes(t *testing.T) {
	st := newFakeStore()
	st.put(testIssuer, "sub-1", User{Key: "u1", Email: "a@example.com", EmailVerified: true})
	auth := &fakeRechecker{
		fakeAuthenticator: fakeAuthenticator{claims: &oidclient.Claims{Sub: "sub-1", Email: "a@example.com"}},
		rechecked:         &oidclient.Claims{Sub: "sub-1", Email: "a@example.com"},
	}
	m := &Middleware{Authenticator: auth, Store: st, Issuer: testIssuer}
	_, u, _ := serveMW(t, m)
	if len(st.syncCalls) != 0 || !u.EmailVerified {
		t.Errorf("syncs = %+v, user = %+v; want no write and a verified user", st.syncCalls, u)
	}
}

// A failed recheck, a failed write, or a recheck answering for a different
// subject must each leave the request authenticated and unverified.
func TestMiddleware_RecheckFaultsDegradeToUnverified(t *testing.T) {
	verified := &oidclient.Claims{Sub: "sub-1", Email: "a@example.com", EmailVerified: true}
	for _, tc := range []struct {
		name      string
		rechecked *oidclient.Claims
		recheck   error
		sync      error
		wantSyncs int
	}{
		{"recheck fails", nil, errors.New("provider down"), nil, 0},
		{"write fails", verified, nil, errors.New("db down"), 1},
		{"subject changed", &oidclient.Claims{Sub: "sub-other", Email: "a@example.com", EmailVerified: true}, nil, nil, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logged []string
			st := newFakeStore()
			st.syncErr = tc.sync
			st.put(testIssuer, "sub-1", User{Key: "u1", Email: "a@example.com"})
			auth := &fakeRechecker{
				fakeAuthenticator: fakeAuthenticator{claims: &oidclient.Claims{Sub: "sub-1", Email: "a@example.com"}},
				rechecked:         tc.rechecked, recheckErr: tc.recheck,
			}
			m := &Middleware{
				Authenticator: auth, Store: st, Issuer: testIssuer,
				Logf: func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) },
			}
			id, u, _ := serveMW(t, m)
			if id == nil || u == nil || id.Subject != "sub-1" {
				t.Fatalf("request lost its user: id=%v u=%v", id, u)
			}
			if u.EmailVerified || id.EmailVerified {
				t.Errorf("request treated as verified after %s", tc.name)
			}
			if len(st.syncCalls) != tc.wantSyncs {
				t.Errorf("syncs = %d, want %d", len(st.syncCalls), tc.wantSyncs)
			}
			if len(logged) == 0 {
				t.Error("fault was not logged")
			}
		})
	}
}

// A negative interval turns the early recheck off; claims that arrive verified
// on their own still promote.
func TestMiddleware_RecheckCanBeDisabled(t *testing.T) {
	st := newFakeStore()
	st.put(testIssuer, "sub-1", User{Key: "u1", Email: "a@example.com"})
	auth := &fakeRechecker{
		fakeAuthenticator: fakeAuthenticator{claims: &oidclient.Claims{Sub: "sub-1", Email: "a@example.com"}},
		rechecked:         &oidclient.Claims{Sub: "sub-1", Email: "a@example.com", EmailVerified: true},
	}
	m := &Middleware{Authenticator: auth, Store: st, Issuer: testIssuer, UnverifiedRecheck: -1}
	serveMW(t, m)
	if auth.rechecks != 0 || len(st.syncCalls) != 0 {
		t.Errorf("rechecks = %d, syncs = %d; want neither", auth.rechecks, len(st.syncCalls))
	}
}

// An Authenticator that cannot renew early (a host's own) still gets
// promotion from whatever claims it returns.
func TestMiddleware_PlainAuthenticatorStillPromotes(t *testing.T) {
	st := newFakeStore()
	st.put(testIssuer, "sub-1", User{Key: "u1", Email: "a@example.com"})
	m := &Middleware{
		Authenticator: &fakeAuthenticator{claims: &oidclient.Claims{Sub: "sub-1", Email: "a@example.com", EmailVerified: true}},
		Store:         st, Issuer: testIssuer,
	}
	_, u, _ := serveMW(t, m)
	if len(st.syncCalls) != 1 || !u.EmailVerified {
		t.Errorf("syncs = %+v, user = %+v; want promoted", st.syncCalls, u)
	}
}

// email_verified describes an address. Claims that say verified but name no
// address attest nothing, and must not mark whatever address the row happens
// to hold as verified -- whether they arrive with the session or from a
// recheck.
func TestMiddleware_VerifiedWithoutAnAddressDoesNotPromote(t *testing.T) {
	for _, tc := range []struct {
		name            string
		session, answer *oidclient.Claims
	}{
		{"session claims", &oidclient.Claims{Sub: "sub-1", EmailVerified: true}, nil},
		{"recheck answer", &oidclient.Claims{Sub: "sub-1", Email: "a@example.com"}, &oidclient.Claims{Sub: "sub-1", EmailVerified: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := newFakeStore()
			st.put(testIssuer, "sub-1", User{Key: "u1", Email: "never-verified@example.com"})
			auth := &fakeRechecker{fakeAuthenticator: fakeAuthenticator{claims: tc.session}, rechecked: tc.answer}
			m := &Middleware{Authenticator: auth, Store: st, Issuer: testIssuer}
			_, u, _ := serveMW(t, m)
			if len(st.syncCalls) != 0 {
				t.Errorf("syncs = %+v, want none", st.syncCalls)
			}
			if u == nil || u.EmailVerified {
				t.Errorf("user = %+v, want present and unverified", u)
			}
		})
	}
}

// A store that keeps refusing the promotion must cost one write per interval,
// not one per request: claims that already say verified skip the recheck and
// its throttle, so the write needs its own.
func TestMiddleware_FailedPromotionBacksOff(t *testing.T) {
	var logged []string
	st := newFakeStore()
	st.syncErr = errors.New("db down")
	st.put(testIssuer, "sub-1", User{Key: "u1", Email: "a@example.com"})
	m := &Middleware{
		Authenticator: &fakeAuthenticator{claims: &oidclient.Claims{Sub: "sub-1", Email: "a@example.com", EmailVerified: true}},
		Store:         st, Issuer: testIssuer,
		Logf: func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) },
	}
	for range 6 {
		if _, u, _ := serveMW(t, m); u == nil || u.EmailVerified {
			t.Fatalf("user = %+v, want present and unverified", u)
		}
	}
	if len(st.syncCalls) != 1 {
		t.Errorf("syncs = %d, want 1 inside the interval", len(st.syncCalls))
	}
	if len(logged) != 1 {
		t.Errorf("logged %d times, want the fault reported once: %v", len(logged), logged)
	}

	// Once the store recovers and the interval has passed, promotion goes through.
	st.syncErr = nil
	m.retry.clear()
	if _, u, _ := serveMW(t, m); !u.EmailVerified {
		t.Error("promotion did not go through after the backoff ended")
	}
}

// One user's failing write must not hold back another's.
func TestMiddleware_BackoffIsPerUser(t *testing.T) {
	st := newFakeStore()
	st.syncErr = errors.New("db down")
	st.put(testIssuer, "sub-1", User{Key: "u1", Email: "a@example.com"})
	st.put(testIssuer, "sub-2", User{Key: "u2", Email: "b@example.com"})
	auth := &fakeAuthenticator{claims: &oidclient.Claims{Sub: "sub-1", Email: "a@example.com", EmailVerified: true}}
	m := &Middleware{Authenticator: auth, Store: st, Issuer: testIssuer}
	serveMW(t, m)
	auth.claims = &oidclient.Claims{Sub: "sub-2", Email: "b@example.com", EmailVerified: true}
	serveMW(t, m)
	if len(st.syncCalls) != 2 {
		t.Errorf("syncs = %d, want one attempt per user", len(st.syncCalls))
	}
}
