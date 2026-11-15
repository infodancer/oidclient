package session

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/infodancer/oidclient"
)

// fakeProvider is a scriptable Provider.
type fakeProvider struct {
	mu            sync.Mutex
	ready         bool
	exchangeN     int
	exchange      func(code, verifier string) (*oidclient.Tokens, *oidclient.Claims, error)
	authorize     string // returned for AuthorizeURL
	register      string // returned for RegisterURL
	lastState     string
	lastVerif     string
	exchangedWith [2]string
}

func (f *fakeProvider) Ready() bool { return f.ready }

func (f *fakeProvider) AuthorizeURL(state, verifier string) string {
	f.lastState, f.lastVerif = state, verifier
	return f.authorize + "?state=" + url.QueryEscape(state)
}

func (f *fakeProvider) RegisterURL(state, verifier string) string {
	f.lastState, f.lastVerif = state, verifier
	return f.register + "?state=" + url.QueryEscape(state)
}

func (f *fakeProvider) Exchange(_ context.Context, code, verifier string) (*oidclient.Tokens, *oidclient.Claims, error) {
	f.mu.Lock()
	f.exchangeN++
	f.exchangedWith = [2]string{code, verifier}
	f.mu.Unlock()
	return f.exchange(code, verifier)
}

func okProvider() *fakeProvider {
	return &fakeProvider{
		ready:     true,
		authorize: "https://idp.example/authorize",
		register:  "https://idp.example/register",
		exchange: func(string, string) (*oidclient.Tokens, *oidclient.Claims, error) {
			return &oidclient.Tokens{AccessToken: "at", RefreshToken: "rt", Expiry: time.Now().Add(time.Hour)},
				&oidclient.Claims{Sub: "user-1", Email: "u@example.com"}, nil
		},
	}
}

func newHandlers(t *testing.T, p Provider, opts ...func(*HandlerConfig)) (*Handlers, *memStore) {
	t.Helper()
	store := newMemStore()
	m := newManager(t, store, &fakeRenewer{}, testKeyring(t))
	cfg := HandlerConfig{Provider: p, Sessions: m}
	for _, o := range opts {
		o(&cfg)
	}
	h, err := NewHandlers(cfg)
	if err != nil {
		t.Fatalf("NewHandlers: %v", err)
	}
	return h, store
}

func cookieNamed(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// cbReq builds a callback request carrying the flow cookies.
func cbReq(query string, cookies map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/auth/callback?"+query, nil)
	for k, v := range cookies {
		r.AddCookie(&http.Cookie{Name: k, Value: v})
	}
	return r
}

func flowCookies(redirect string) map[string]string {
	m := map[string]string{oidclient.CookieState: "st-1", oidclient.CookieVerifier: "ver-1"}
	if redirect != "" {
		m[oidclient.CookieRedirect] = redirect
	}
	return m
}

func TestNewHandlers_RequiredConfig(t *testing.T) {
	m := newManager(t, newMemStore(), &fakeRenewer{}, testKeyring(t))
	if _, err := NewHandlers(HandlerConfig{Sessions: m}); err == nil {
		t.Error("accepted a missing Provider")
	}
	if _, err := NewHandlers(HandlerConfig{Provider: okProvider()}); err == nil {
		t.Error("accepted missing Sessions")
	}
}

// --- Login / Register --------------------------------------------------------

func TestLogin_NotReadyIs503AndSetsNoFlow(t *testing.T) {
	p := okProvider()
	p.ready = false
	h, _ := newHandlers(t, p)
	rec := httptest.NewRecorder()
	h.Login().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Errorf("cookies set while the provider is not ready: %v", rec.Result().Cookies())
	}
}

func TestLogin_RedirectsToTheProviderWithAMatchingFlow(t *testing.T) {
	p := okProvider()
	h, _ := newHandlers(t, p)
	rec := httptest.NewRecorder()
	h.Login().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login?return=/account", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://idp.example/authorize?state=") {
		t.Fatalf("Location = %q", loc)
	}
	st, ver, red := cookieNamed(rec, oidclient.CookieState), cookieNamed(rec, oidclient.CookieVerifier), cookieNamed(rec, oidclient.CookieRedirect)
	if st == nil || ver == nil || red == nil {
		t.Fatalf("flow cookies missing: state=%v verifier=%v redirect=%v", st, ver, red)
	}
	if st.Value != p.lastState || ver.Value != p.lastVerif {
		t.Error("the cookies do not match the state and verifier sent to the provider")
	}
	if red.Value != "/account" {
		t.Errorf("redirect cookie = %q, want /account", red.Value)
	}
}

func TestLogin_RejectsOffSiteReturnTargets(t *testing.T) {
	for _, bad := range []string{"https://evil.example/", "//evil.example/x", "/\\evil.example", "javascript:alert(1)", "evil"} {
		h, _ := newHandlers(t, okProvider())
		rec := httptest.NewRecorder()
		h.Login().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login?return="+url.QueryEscape(bad), nil))
		if c := cookieNamed(rec, oidclient.CookieRedirect); c != nil && c.Value != "" {
			t.Errorf("return=%q was stored as the post-login redirect: %q", bad, c.Value)
		}
	}
}

func TestLogin_ReusesAnInProgressFlow(t *testing.T) {
	p := okProvider()
	h, _ := newHandlers(t, p)
	first := httptest.NewRecorder()
	h.Login().ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/login", nil))
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	for _, c := range first.Result().Cookies() {
		req.AddCookie(c)
	}
	h.Login().ServeHTTP(httptest.NewRecorder(), req)
	if p.lastState != cookieNamed(first, oidclient.CookieState).Value {
		t.Error("a second tab started a new flow, which would invalidate the first tab's callback")
	}
}

func TestRegister_UsesTheRegistrationURL(t *testing.T) {
	h, _ := newHandlers(t, okProvider())
	rec := httptest.NewRecorder()
	h.Register().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/register", nil))
	if rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), "https://idp.example/register?state=") {
		t.Errorf("status %d, Location %q", rec.Code, rec.Header().Get("Location"))
	}
}

// --- Callback ------------------------------------------------------------------

func TestCallback_NotReadyIs503(t *testing.T) {
	p := okProvider()
	p.ready = false
	h, _ := newHandlers(t, p)
	rec := httptest.NewRecorder()
	h.Callback().ServeHTTP(rec, cbReq("code=c&state=st-1", flowCookies("")))
	if rec.Code != http.StatusServiceUnavailable || p.exchangeN != 0 {
		t.Errorf("status %d, exchanges %d", rec.Code, p.exchangeN)
	}
}

func TestCallback_RejectsBadRequestsWithoutExchanging(t *testing.T) {
	cases := []struct {
		name    string
		query   string
		cookies map[string]string
		want    int
	}{
		{"upstream error", "error=access_denied&state=st-1", flowCookies(""), http.StatusUnauthorized},
		{"no code", "state=st-1", flowCookies(""), http.StatusBadRequest},
		{"no state", "code=c", flowCookies(""), http.StatusBadRequest},
		{"no flow cookie", "code=c&state=st-1", nil, http.StatusBadRequest},
		{"state mismatch", "code=c&state=other", flowCookies(""), http.StatusBadRequest},
		{"empty state cookie matches empty state", "code=c&state=", map[string]string{oidclient.CookieState: "", oidclient.CookieVerifier: "ver-1"}, http.StatusBadRequest},
		{"no verifier", "code=c&state=st-1", map[string]string{oidclient.CookieState: "st-1"}, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := okProvider()
			h, store := newHandlers(t, p)
			rec := httptest.NewRecorder()
			h.Callback().ServeHTTP(rec, cbReq(tc.query, tc.cookies))
			if rec.Code != tc.want {
				t.Errorf("status = %d, want %d", rec.Code, tc.want)
			}
			if p.exchangeN != 0 {
				t.Error("the code was exchanged for a request that should have been rejected first")
			}
			if len(store.rows) != 0 || cookieNamed(rec, "sid") != nil {
				t.Error("a session was started")
			}
		})
	}
}

func TestCallback_SuccessStartsASessionAndRedirects(t *testing.T) {
	p := okProvider()
	h, store := newHandlers(t, p)
	rec := httptest.NewRecorder()
	h.Callback().ServeHTTP(rec, cbReq("code=the-code&state=st-1", flowCookies("/account")))
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/account" {
		t.Fatalf("status %d, Location %q, want 302 /account", rec.Code, rec.Header().Get("Location"))
	}
	if p.exchangedWith != [2]string{"the-code", "ver-1"} {
		t.Errorf("exchanged with %v, want the code and the PKCE verifier from the flow", p.exchangedWith)
	}
	if len(store.rows) != 1 {
		t.Fatalf("sessions stored = %d, want 1", len(store.rows))
	}
	sid := cookieNamed(rec, "sid")
	if sid == nil || sid.Value == "" || !sid.HttpOnly {
		t.Fatalf("session cookie missing or not HttpOnly: %+v", sid)
	}
	if _, ok := store.rows[sid.Value]; !ok {
		t.Error("the cookie does not name the stored session")
	}
	for _, name := range []string{oidclient.CookieState, oidclient.CookieVerifier, oidclient.CookieRedirect} {
		if c := cookieNamed(rec, name); c == nil || c.MaxAge >= 0 {
			t.Errorf("flow cookie %s was not cleared: %+v", name, c)
		}
	}
}

func TestCallback_DefaultsToTheRoot(t *testing.T) {
	h, _ := newHandlers(t, okProvider())
	rec := httptest.NewRecorder()
	h.Callback().ServeHTTP(rec, cbReq("code=c&state=st-1", flowCookies("")))
	if rec.Header().Get("Location") != "/" {
		t.Errorf("Location = %q, want /", rec.Header().Get("Location"))
	}
}

// A redirect cookie can be planted from a sibling subdomain, so the callback
// re-validates it instead of trusting what Login stored.
func TestCallback_IgnoresAPlantedOffSiteRedirect(t *testing.T) {
	// A backslash cannot be tested here: net/http drops it from a cookie value
	// before the handler sees it, leaving a harmless local path. The Login
	// test covers "/\\evil" arriving through the query string.
	for _, bad := range []string{"https://evil.example/", "//evil.example/x"} {
		h, _ := newHandlers(t, okProvider())
		rec := httptest.NewRecorder()
		h.Callback().ServeHTTP(rec, cbReq("code=c&state=st-1", flowCookies(bad)))
		if loc := rec.Header().Get("Location"); loc != "/" {
			t.Errorf("planted redirect %q sent the user to %q", bad, loc)
		}
	}
}

func TestCallback_ExchangeFailureIsAGenericBadGateway(t *testing.T) {
	p := okProvider()
	p.exchange = func(string, string) (*oidclient.Tokens, *oidclient.Claims, error) {
		return nil, nil, errors.New("invalid_grant: code expired for client abc123")
	}
	var logged string
	h, store := newHandlers(t, p, func(c *HandlerConfig) {
		c.Logf = func(f string, a ...any) { logged = f }
	})
	rec := httptest.NewRecorder()
	h.Callback().ServeHTTP(rec, cbReq("code=c&state=st-1", flowCookies("")))
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "invalid_grant") || strings.Contains(rec.Body.String(), "abc123") {
		t.Errorf("the response leaks the provider's error: %q", rec.Body)
	}
	if len(store.rows) != 0 || logged == "" {
		t.Errorf("sessions %d, logged %q", len(store.rows), logged)
	}
}

func TestCallback_OnAuthenticatedGatesTheLogin(t *testing.T) {
	p := okProvider()
	h, store := newHandlers(t, p, func(c *HandlerConfig) {
		c.OnAuthenticated = func(*http.Request, *oidclient.Claims) (string, error) {
			return "", errors.New("account disabled")
		}
	})
	rec := httptest.NewRecorder()
	h.Callback().ServeHTTP(rec, cbReq("code=c&state=st-1", flowCookies("")))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	if len(store.rows) != 0 || cookieNamed(rec, "sid") != nil {
		t.Error("a session was started although OnAuthenticated refused the login")
	}
	if strings.Contains(rec.Body.String(), "disabled") {
		t.Errorf("the response leaks the hook's error: %q", rec.Body)
	}
}

func TestCallback_OnAuthenticatedSeesTheClaimsAndPicksTheDefaultRedirect(t *testing.T) {
	var got string
	h, _ := newHandlers(t, okProvider(), func(c *HandlerConfig) {
		c.OnAuthenticated = func(_ *http.Request, cl *oidclient.Claims) (string, error) {
			got = cl.Sub
			return "/welcome", nil
		}
	})
	rec := httptest.NewRecorder()
	h.Callback().ServeHTTP(rec, cbReq("code=c&state=st-1", flowCookies("")))
	if got != "user-1" || rec.Header().Get("Location") != "/welcome" {
		t.Errorf("hook saw %q, Location %q", got, rec.Header().Get("Location"))
	}
	// An explicit return target still wins over the hook's default.
	rec = httptest.NewRecorder()
	h.Callback().ServeHTTP(rec, cbReq("code=c&state=st-1", flowCookies("/account")))
	if rec.Header().Get("Location") != "/account" {
		t.Errorf("Location = %q, want the explicit /account", rec.Header().Get("Location"))
	}
}

// --- Logout --------------------------------------------------------------------

func TestLogout_PostDestroysTheSession(t *testing.T) {
	h, store := newHandlers(t, okProvider())
	login := httptest.NewRecorder()
	h.Callback().ServeHTTP(login, cbReq("code=c&state=st-1", flowCookies("")))
	sid := cookieNamed(login, "sid")
	if sid == nil || len(store.rows) != 1 {
		t.Fatal("no session to log out of")
	}

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(sid)
	rec := httptest.NewRecorder()
	h.Logout().ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
		t.Errorf("status %d, Location %q, want 303 /", rec.Code, rec.Header().Get("Location"))
	}
	if len(store.rows) != 0 {
		t.Error("the server-side session survived logout")
	}
	if c := cookieNamed(rec, "sid"); c == nil || c.MaxAge >= 0 {
		t.Errorf("session cookie not cleared: %+v", c)
	}
}

// A state-changing GET can be fired by any page the user visits (an <img> tag
// is enough), so logout accepts POST only.
func TestLogout_RefusesGET(t *testing.T) {
	h, store := newHandlers(t, okProvider())
	login := httptest.NewRecorder()
	h.Callback().ServeHTTP(login, cbReq("code=c&state=st-1", flowCookies("")))
	req := httptest.NewRequest(http.MethodGet, "/logout", nil)
	req.AddCookie(cookieNamed(login, "sid"))
	rec := httptest.NewRecorder()
	h.Logout().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != http.MethodPost {
		t.Errorf("status %d, Allow %q, want 405 POST", rec.Code, rec.Header().Get("Allow"))
	}
	if len(store.rows) != 1 {
		t.Error("a GET ended the session")
	}
}

func TestLogout_WithNoSessionStillRedirects(t *testing.T) {
	h, _ := newHandlers(t, okProvider(), func(c *HandlerConfig) { c.LogoutRedirect = "/bye" })
	rec := httptest.NewRecorder()
	h.Logout().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/logout", nil))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/bye" {
		t.Errorf("status %d, Location %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestLogoutRedirectMustBeLocal(t *testing.T) {
	m := newManager(t, newMemStore(), &fakeRenewer{}, testKeyring(t))
	if _, err := NewHandlers(HandlerConfig{Provider: okProvider(), Sessions: m, LogoutRedirect: "https://evil.example/"}); err == nil {
		t.Error("accepted an off-site LogoutRedirect")
	}
}
