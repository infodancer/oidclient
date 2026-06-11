package oidclient

import "net/http"

const (
	// Default cookie names for the OIDC authorization flow.
	CookieVerifier = "oauth_verifier"
	CookieState    = "oauth_state"
	CookieRedirect = "oauth_redirect"
)

// IsSecure returns true if the request arrived over TLS or via an HTTPS proxy.
func IsSecure(r *http.Request) bool {
	return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
}

// SetFlowCookie writes an HttpOnly cookie used during the OIDC flow. The
// cookie is session-lifetime: the flow must survive however long the user
// leaves the IdP's login page open, and the state/verifier nonces derive no
// security from a fixed expiry -- the authorization code and PKCE binding do.
func SetFlowCookie(w http.ResponseWriter, name, value string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearFlowCookies expires all OIDC flow cookies.
func ClearFlowCookies(w http.ResponseWriter) {
	for _, name := range []string{CookieVerifier, CookieState, CookieRedirect} {
		http.SetCookie(w, &http.Cookie{Name: name, Path: "/", MaxAge: -1})
	}
}

// SetSessionCookie writes the JWT as an HttpOnly session cookie.
func SetSessionCookie(w http.ResponseWriter, name, token string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearSessionCookie expires the session cookie.
func ClearSessionCookie(w http.ResponseWriter, name string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// FlowCookieValue reads a named cookie value, returning "" if absent.
func FlowCookieValue(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}
