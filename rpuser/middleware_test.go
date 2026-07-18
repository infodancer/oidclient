package rpuser

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

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

// TestMiddleware_ReadOnly pins the login-only sync decision: the per-request
// path must never write, even when the session's claims differ from the
// stored row.
func TestMiddleware_ReadOnly(t *testing.T) {
	st := newFakeStore()
	st.put(testIssuer, "sub-1", User{Key: "u1", Email: "old@example.com", EmailVerified: false})
	m := &Middleware{
		Authenticator: &fakeAuthenticator{claims: &oidclient.Claims{Sub: "sub-1", Email: "new@example.com", EmailVerified: true}},
		Store:         st,
		Issuer:        testIssuer,
	}
	serveMW(t, m)
	if len(st.syncCalls) != 0 || len(st.createCalls) != 0 {
		t.Errorf("per-request path wrote to the store: syncs=%d creates=%d", len(st.syncCalls), len(st.createCalls))
	}
}
