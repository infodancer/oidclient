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
