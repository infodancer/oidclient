package oidclient

import "net/http"

// CallbackOptions customizes the app-specific parts of CallbackHandler.
// The zero value is a working configuration.
type CallbackOptions struct {
	// OnAuthenticated runs after a successful code exchange and before the
	// session cookie is written -- the place to provision or update a local
	// user from the claims. The returned defaultRedirect, when non-empty, is
	// the post-login destination used if the flow carries no explicit
	// redirect (e.g. a welcome page for new accounts). A returned error
	// aborts the login: no session cookie is set and the response is a 500.
	OnAuthenticated func(r *http.Request, accessToken string, claims *Claims) (defaultRedirect string, err error)

	// SanitizeRedirect filters the redirect-cookie value before use; return
	// "" to reject it. Apps should restrict the destination to local paths
	// as defense in depth against a planted cookie.
	SanitizeRedirect func(value string) string

	// Finish completes the response after the session cookie is set,
	// replacing the default 302 to redirectTo. For flows that must not
	// navigate, such as a login popup that posts a message to its opener
	// and closes.
	Finish func(w http.ResponseWriter, r *http.Request, redirectTo string)

	// Logf receives diagnostic messages for failed callbacks (token exchange
	// and provisioning errors, upstream error params). Nil disables logging.
	Logf func(format string, args ...any)
}

// CallbackHandler returns the redirect-URI endpoint for the authorization
// code flow: it surfaces upstream errors, validates the state nonce against
// the flow cookie, exchanges the code with PKCE, invokes OnAuthenticated,
// writes the session cookie, clears the flow cookies, and sends the user to
// the destination from the flow's redirect cookie (default "/").
func (c *Client) CallbackHandler(opts CallbackOptions) http.Handler {
	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if errParam := r.URL.Query().Get("error"); errParam != "" {
			logf("oidclient: callback error from provider: %s", errParam)
			http.Error(w, "authentication error", http.StatusUnauthorized)
			return
		}

		code := r.URL.Query().Get("code")
		stateParam := r.URL.Query().Get("state")
		if code == "" || stateParam == "" {
			http.Error(w, "missing code or state", http.StatusBadRequest)
			return
		}

		storedState := FlowCookieValue(r, CookieState)
		if storedState == "" || storedState != stateParam {
			http.Error(w, "invalid state parameter", http.StatusBadRequest)
			return
		}

		verifier := FlowCookieValue(r, CookieVerifier)
		if verifier == "" {
			http.Error(w, "missing PKCE verifier", http.StatusBadRequest)
			return
		}

		accessToken, claims, err := c.ExchangeCode(r.Context(), code, verifier)
		if err != nil {
			logf("oidclient: callback token exchange: %v", err)
			http.Error(w, "authentication failed", http.StatusBadGateway)
			return
		}

		redirectTo := FlowCookieValue(r, CookieRedirect)
		if opts.SanitizeRedirect != nil {
			redirectTo = opts.SanitizeRedirect(redirectTo)
		}

		if opts.OnAuthenticated != nil {
			defaultRedirect, err := opts.OnAuthenticated(r, accessToken, claims)
			if err != nil {
				logf("oidclient: callback OnAuthenticated: %v", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if redirectTo == "" {
				redirectTo = defaultRedirect
			}
		}
		if redirectTo == "" {
			redirectTo = "/"
		}

		secure := IsSecure(r)
		SetSessionCookie(w, c.CookieName(), accessToken, secure)
		ClearFlowCookies(w)

		if opts.Finish != nil {
			opts.Finish(w, r, redirectTo)
			return
		}
		http.Redirect(w, r, redirectTo, http.StatusFound)
	})
}
