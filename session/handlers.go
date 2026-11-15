package session

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"

	"github.com/infodancer/oidclient"
)

// Provider is the slice of *oidclient.Client the login handlers need. The
// concrete client satisfies it; tests substitute a fake.
type Provider interface {
	// Ready reports whether discovery has completed. A lazy client that has
	// not reached the IdP yet cannot start or finish a flow.
	Ready() bool
	AuthorizeURL(state, verifier string) string
	RegisterURL(state, verifier string) string
	Exchange(ctx context.Context, code, verifier string) (*oidclient.Tokens, *oidclient.Claims, error)
}

var _ Provider = (*oidclient.Client)(nil)

// HandlerConfig builds the login handlers. Provider and Sessions are required.
type HandlerConfig struct {
	Provider Provider
	Sessions *Manager

	// OnAuthenticated runs after a successful code exchange and before the
	// session starts: the place to provision or sync a local user from the
	// claims. An error aborts the login (no session, a generic 500). The
	// returned redirect, when it is a local path, is the destination used
	// only if the flow carried no explicit return target of its own.
	OnAuthenticated func(r *http.Request, claims *oidclient.Claims) (defaultRedirect string, err error)

	// LogoutRedirect is where Logout sends the browser; it must be a local
	// path. Empty means "/".
	LogoutRedirect string

	// Logf receives diagnostics: upstream error params, failed exchanges and
	// session or hook failures. Nil discards them. The HTTP responses never
	// carry these details.
	Logf func(format string, args ...any)
}

// Handlers are the three endpoints of the server-side-session login flow, for
// a relying party that keeps tokens server-side (see this package's Manager)
// rather than in a browser cookie. Mount them on routes of your choosing, for
// example GET /login, GET /auth/callback and POST /logout.
//
// Open-redirect defense is applied on both sides: the "return" parameter is
// reduced to a local path when Login stores it, and the redirect cookie is
// reduced again when Callback reads it back, since the cookie can be planted
// from a sibling subdomain.
type Handlers struct {
	cfg HandlerConfig
}

// NewHandlers validates cfg and returns the handlers.
func NewHandlers(cfg HandlerConfig) (*Handlers, error) {
	if cfg.Provider == nil {
		return nil, errors.New("oidclient/session: HandlerConfig.Provider is required")
	}
	if cfg.Sessions == nil {
		return nil, errors.New("oidclient/session: HandlerConfig.Sessions is required")
	}
	if cfg.LogoutRedirect == "" {
		cfg.LogoutRedirect = "/"
	}
	if oidclient.LocalPath(cfg.LogoutRedirect) == "" {
		return nil, errors.New("oidclient/session: HandlerConfig.LogoutRedirect must be a local path")
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	return &Handlers{cfg: cfg}, nil
}

// Login starts the authorization-code flow (PKCE). It reuses a flow already in
// progress so two tabs do not overwrite each other's state and fail the
// callback. The optional "return" query parameter names the local path to land
// on afterwards.
func (h *Handlers) Login() http.Handler {
	return h.start(h.cfg.Provider.AuthorizeURL, "sign-in")
}

// Register is Login, but lands on the IdP's registration page.
func (h *Handlers) Register() http.Handler {
	return h.start(h.cfg.Provider.RegisterURL, "registration")
}

func (h *Handlers) start(target func(state, verifier string) string, what string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A lazy client still discovering the IdP has no authorize URL yet;
		// degrade this endpoint rather than redirecting to an empty one.
		if !h.cfg.Provider.Ready() {
			http.Error(w, what+" temporarily unavailable, please try again shortly", http.StatusServiceUnavailable)
			return
		}
		state, verifier, err := oidclient.GetOrCreateFlow(w, r, oidclient.LocalPath(r.URL.Query().Get("return")))
		if err != nil {
			h.cfg.Logf("oidclient/session: start flow: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, target(state, verifier), http.StatusFound)
	})
}

// Callback completes the flow: it surfaces an upstream error, checks the state
// against the flow cookie, exchanges the code with the PKCE verifier, runs
// OnAuthenticated, starts the server-side session, clears the flow cookies and
// redirects. Every rejection happens before the code is exchanged.
func (h *Handlers) Callback() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !h.cfg.Provider.Ready() {
			http.Error(w, "authentication temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		q := r.URL.Query()
		if e := q.Get("error"); e != "" {
			h.cfg.Logf("oidclient/session: callback reported an error: %s", e)
			http.Error(w, "authentication error", http.StatusUnauthorized)
			return
		}
		code, state := q.Get("code"), q.Get("state")
		if code == "" || state == "" {
			http.Error(w, "missing code or state", http.StatusBadRequest)
			return
		}
		stored := oidclient.FlowCookieValue(r, oidclient.CookieState)
		if stored == "" || subtle.ConstantTimeCompare([]byte(stored), []byte(state)) != 1 {
			http.Error(w, "invalid state parameter", http.StatusBadRequest)
			return
		}
		verifier := oidclient.FlowCookieValue(r, oidclient.CookieVerifier)
		if verifier == "" {
			http.Error(w, "missing PKCE verifier", http.StatusBadRequest)
			return
		}

		tokens, claims, err := h.cfg.Provider.Exchange(r.Context(), code, verifier)
		if err != nil {
			h.cfg.Logf("oidclient/session: token exchange: %v", err)
			http.Error(w, "authentication failed", http.StatusBadGateway)
			return
		}

		fallback := ""
		if h.cfg.OnAuthenticated != nil {
			fallback, err = h.cfg.OnAuthenticated(r, claims)
			if err != nil {
				h.cfg.Logf("oidclient/session: OnAuthenticated: %v", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
		}
		if err := h.cfg.Sessions.Start(w, r, tokens, claims); err != nil {
			h.cfg.Logf("oidclient/session: start session: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		redirectTo := oidclient.LocalPath(oidclient.FlowCookieValue(r, oidclient.CookieRedirect))
		if redirectTo == "" {
			redirectTo = oidclient.LocalPath(fallback)
		}
		if redirectTo == "" {
			redirectTo = "/"
		}
		oidclient.ClearFlowCookies(w)
		http.Redirect(w, r, redirectTo, http.StatusFound)
	})
}

// Logout destroys the server-side session, expires its cookie and redirects to
// LogoutRedirect. It accepts POST only: a state-changing GET can be triggered
// by any page the user visits, an <img> tag being enough. Render the sign-out
// control as a form.
func (h *Handlers) Logout() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.cfg.Sessions.Destroy(w, r)
		http.Redirect(w, r, h.cfg.LogoutRedirect, http.StatusSeeOther)
	})
}
