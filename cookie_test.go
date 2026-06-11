package oidclient

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSetFlowCookie_SessionCookie(t *testing.T) {
	w := httptest.NewRecorder()
	SetFlowCookie(w, CookieState, "somevalue", true)

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("got %d cookies, want 1", len(cookies))
	}
	c := cookies[0]
	// Session cookie: the flow must survive however long the user leaves the
	// IdP's login page open, so the cookie carries no fixed expiry.
	if c.MaxAge != 0 || !c.Expires.IsZero() {
		t.Errorf("flow cookie has expiry (MaxAge=%d, Expires=%v), want session cookie", c.MaxAge, c.Expires)
	}
	if !c.HttpOnly {
		t.Errorf("flow cookie not HttpOnly")
	}
	if !c.Secure {
		t.Errorf("flow cookie not Secure despite secure=true")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", c.SameSite)
	}
	if c.Path != "/" {
		t.Errorf("Path = %q, want /", c.Path)
	}
}

func TestGetOrCreateFlow_New(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/protected", nil)
	w := httptest.NewRecorder()

	state, verifier, err := GetOrCreateFlow(w, r, "/protected")
	if err != nil {
		t.Fatalf("GetOrCreateFlow: %v", err)
	}
	if state == "" || verifier == "" {
		t.Fatalf("empty state %q or verifier %q", state, verifier)
	}

	got := map[string]string{}
	for _, c := range w.Result().Cookies() {
		got[c.Name] = c.Value
	}
	if got[CookieState] != state {
		t.Errorf("state cookie = %q, want %q", got[CookieState], state)
	}
	if got[CookieVerifier] != verifier {
		t.Errorf("verifier cookie = %q, want %q", got[CookieVerifier], verifier)
	}
	if got[CookieRedirect] != "/protected" {
		t.Errorf("redirect cookie = %q, want /protected", got[CookieRedirect])
	}
}

// Concurrent unauthenticated requests must share one flow: a request that
// already carries flow cookies reuses them rather than overwriting the state
// another in-flight redirect is about to depend on.
func TestGetOrCreateFlow_ReusesExisting(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/other", nil)
	r.AddCookie(&http.Cookie{Name: CookieState, Value: "existing-state"})
	r.AddCookie(&http.Cookie{Name: CookieVerifier, Value: "existing-verifier"})
	w := httptest.NewRecorder()

	state, verifier, err := GetOrCreateFlow(w, r, "/other")
	if err != nil {
		t.Fatalf("GetOrCreateFlow: %v", err)
	}
	if state != "existing-state" || verifier != "existing-verifier" {
		t.Errorf("got (%q, %q), want existing values reused", state, verifier)
	}

	for _, c := range w.Result().Cookies() {
		switch c.Name {
		case CookieState, CookieVerifier:
			t.Errorf("reuse must not rewrite %s", c.Name)
		case CookieRedirect:
			if c.Value != "/other" {
				t.Errorf("redirect cookie = %q, want /other", c.Value)
			}
		}
	}
}

// A half-present flow (only one of state/verifier survived) is unusable;
// both must be regenerated together.
func TestGetOrCreateFlow_PartialCookiesRegenerate(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: CookieState, Value: "orphan-state"})
	w := httptest.NewRecorder()

	state, verifier, err := GetOrCreateFlow(w, r, "/")
	if err != nil {
		t.Fatalf("GetOrCreateFlow: %v", err)
	}
	if state == "orphan-state" {
		t.Errorf("orphaned state must not be reused without its verifier")
	}
	if state == "" || verifier == "" {
		t.Fatalf("empty state %q or verifier %q", state, verifier)
	}

	got := map[string]string{}
	for _, c := range w.Result().Cookies() {
		got[c.Name] = c.Value
	}
	if got[CookieState] != state || got[CookieVerifier] != verifier {
		t.Errorf("regenerated values not written to cookies: %v", got)
	}
}
