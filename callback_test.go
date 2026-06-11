package oidclient

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// callbackReq builds a callback request carrying the standard flow cookies.
func callbackReq(query string, cookies map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/auth/callback"+query, nil)
	for name, value := range cookies {
		r.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	return r
}

func flowCookies(state string) map[string]string {
	return map[string]string{
		CookieState:    state,
		CookieVerifier: "test-verifier",
	}
}

func TestCallbackHandler_Success(t *testing.T) {
	srv, issuer, _ := fakeProvider(t)
	c := newTestClient(t, srv, issuer)
	h := c.CallbackHandler(CallbackOptions{})

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, callbackReq("?code=fake-code&state=st1", flowCookies("st1")))

	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body: %s", rr.Code, rr.Body)
	}
	if loc := rr.Header().Get("Location"); loc != "/" {
		t.Errorf("Location = %q, want /", loc)
	}

	var sessionSet bool
	cleared := map[string]bool{}
	for _, ck := range rr.Result().Cookies() {
		switch ck.Name {
		case "test_jwt":
			sessionSet = ck.Value != ""
			if !ck.HttpOnly {
				t.Errorf("session cookie not HttpOnly")
			}
		case CookieState, CookieVerifier, CookieRedirect:
			if ck.MaxAge < 0 {
				cleared[ck.Name] = true
			}
		}
	}
	if !sessionSet {
		t.Errorf("session cookie not set")
	}
	if len(cleared) != 3 {
		t.Errorf("flow cookies cleared = %v, want all three", cleared)
	}
}

func TestCallbackHandler_RedirectCookieHonored(t *testing.T) {
	srv, issuer, _ := fakeProvider(t)
	c := newTestClient(t, srv, issuer)
	h := c.CallbackHandler(CallbackOptions{})

	cookies := flowCookies("st1")
	cookies[CookieRedirect] = "/articles/42"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, callbackReq("?code=fake-code&state=st1", cookies))

	if loc := rr.Header().Get("Location"); loc != "/articles/42" {
		t.Errorf("Location = %q, want /articles/42", loc)
	}
}

func TestCallbackHandler_Failures(t *testing.T) {
	srv, issuer, _ := fakeProvider(t)
	c := newTestClient(t, srv, issuer)
	h := c.CallbackHandler(CallbackOptions{})

	tests := []struct {
		name    string
		query   string
		cookies map[string]string
		want    int
	}{
		{"upstream error param", "?error=access_denied", flowCookies("st1"), http.StatusUnauthorized},
		{"missing code", "?state=st1", flowCookies("st1"), http.StatusBadRequest},
		{"missing state", "?code=fake-code", flowCookies("st1"), http.StatusBadRequest},
		{"state mismatch", "?code=fake-code&state=WRONG", flowCookies("st1"), http.StatusBadRequest},
		{"missing state cookie", "?code=fake-code&state=st1", map[string]string{CookieVerifier: "v"}, http.StatusBadRequest},
		{"missing verifier", "?code=fake-code&state=st1", map[string]string{CookieState: "st1"}, http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, callbackReq(tt.query, tt.cookies))
			if rr.Code != tt.want {
				t.Errorf("status = %d, want %d", rr.Code, tt.want)
			}
			for _, ck := range rr.Result().Cookies() {
				if ck.Name == "test_jwt" {
					t.Errorf("session cookie must not be set on failure")
				}
			}
		})
	}
}

func TestCallbackHandler_OnAuthenticated(t *testing.T) {
	srv, issuer, _ := fakeProvider(t)
	c := newTestClient(t, srv, issuer)

	var gotSub, gotToken string
	h := c.CallbackHandler(CallbackOptions{
		OnAuthenticated: func(r *http.Request, accessToken string, claims *Claims) (string, error) {
			gotSub = claims.Sub
			gotToken = accessToken
			return "/welcome", nil
		},
	})

	// No redirect cookie: the hook's default destination wins.
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, callbackReq("?code=fake-code&state=st1", flowCookies("st1")))
	if loc := rr.Header().Get("Location"); loc != "/welcome" {
		t.Errorf("Location = %q, want /welcome", loc)
	}
	if gotSub != "user-from-token" {
		t.Errorf("claims.Sub = %q, want user-from-token", gotSub)
	}
	if gotToken == "" {
		t.Errorf("hook did not receive the access token")
	}

	// Explicit redirect cookie: it wins over the hook's default.
	cookies := flowCookies("st1")
	cookies[CookieRedirect] = "/explicit"
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, callbackReq("?code=fake-code&state=st1", cookies))
	if loc := rr.Header().Get("Location"); loc != "/explicit" {
		t.Errorf("Location = %q, want /explicit", loc)
	}
}

func TestCallbackHandler_OnAuthenticatedError(t *testing.T) {
	srv, issuer, _ := fakeProvider(t)
	c := newTestClient(t, srv, issuer)
	h := c.CallbackHandler(CallbackOptions{
		OnAuthenticated: func(*http.Request, string, *Claims) (string, error) {
			return "", errors.New("provisioning failed")
		},
	})

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, callbackReq("?code=fake-code&state=st1", flowCookies("st1")))

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rr.Code)
	}
	for _, ck := range rr.Result().Cookies() {
		if ck.Name == "test_jwt" {
			t.Errorf("session cookie must not be set when provisioning fails")
		}
	}
}

func TestCallbackHandler_SanitizeRedirect(t *testing.T) {
	srv, issuer, _ := fakeProvider(t)
	c := newTestClient(t, srv, issuer)
	h := c.CallbackHandler(CallbackOptions{
		SanitizeRedirect: func(v string) string {
			if !strings.HasPrefix(v, "/") {
				return ""
			}
			return v
		},
	})

	cookies := flowCookies("st1")
	cookies[CookieRedirect] = "https://evil.example.com/"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, callbackReq("?code=fake-code&state=st1", cookies))

	if loc := rr.Header().Get("Location"); loc != "/" {
		t.Errorf("rejected redirect should fall back to /, got %q", loc)
	}
}

func TestCallbackHandler_FinishHook(t *testing.T) {
	srv, issuer, _ := fakeProvider(t)
	c := newTestClient(t, srv, issuer)
	h := c.CallbackHandler(CallbackOptions{
		Finish: func(w http.ResponseWriter, r *http.Request, redirectTo string) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "popup-close:%s", redirectTo)
		},
	})

	cookies := flowCookies("st1")
	cookies[CookieRedirect] = "/after"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, callbackReq("?code=fake-code&state=st1", cookies))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 from Finish hook", rr.Code)
	}
	if got := rr.Body.String(); got != "popup-close:/after" {
		t.Errorf("body = %q, want popup-close:/after", got)
	}
	var sessionSet bool
	for _, ck := range rr.Result().Cookies() {
		if ck.Name == "test_jwt" && ck.Value != "" {
			sessionSet = true
		}
	}
	if !sessionSet {
		t.Errorf("session cookie must be set before Finish runs")
	}
}
