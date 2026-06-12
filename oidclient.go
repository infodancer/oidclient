// Package oidclient is an OIDC relying party library for web applications
// authenticating against an OpenID Connect provider (designed for use with
// infodancer/webauth but compatible with any spec-compliant IdP).
//
// It wraps [github.com/coreos/go-oidc/v3] for discovery, JWKS, and token
// verification, and [golang.org/x/oauth2] for the authorization code flow
// with PKCE. Cookie helpers and a convenience API are layered on top.
package oidclient

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Sentinel errors returned by Validate, ValidateCookie, and ExchangeCode.
var (
	ErrNoCookie   = errors.New("oidclient: missing auth cookie")
	ErrNoIDToken  = errors.New("oidclient: token response missing id_token")
	ErrMissingSub = errors.New("oidclient: token missing sub claim")

	// ErrNotReady is returned by token operations on a [NewLazy] client whose
	// provider discovery has not yet succeeded. Treat it as "anonymous" on
	// validation paths and as "sign-in temporarily unavailable" on flow paths.
	ErrNotReady = errors.New("oidclient: provider not ready")
)

// Claims holds the JWT claims extracted from an ID or access token.
type Claims struct {
	Sub           string   `json:"sub"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified,omitempty"`
	Name          string   `json:"name"`
	Roles         []string `json:"roles,omitempty"`
}

// Config configures the OIDC client.
type Config struct {
	// IssuerURL is the OIDC issuer (e.g. "https://auth.example.com/t/mytenant").
	// Used for discovery and token verification. Required.
	IssuerURL string

	// CookieName is the name of the HttpOnly cookie storing the JWT session token.
	CookieName string

	// ClientID is this application's pre-registered OIDC client ID. Used as-is
	// when the provider does not advertise a registration_endpoint. When the
	// provider supports RFC 7591 dynamic client registration, this field is
	// ignored and the server-assigned client_id is used instead — query the
	// runtime value via Client.ClientID after New returns.
	ClientID string

	// ClientName is optional client metadata (RFC 7591 §2) sent during dynamic
	// registration. Servers may use it for display in admin UIs and consent
	// screens. Ignored when the provider does not advertise a registration_endpoint.
	ClientName string

	// ClientSecret is the static secret for a confidential client (e.g. a Google
	// "Web application" credential). Set it together with a pre-registered
	// ClientID for providers that issue a secret and do not support RFC 7591
	// dynamic registration; it is sent in the token-exchange request body
	// alongside the PKCE verifier. Leave empty for public PKCE clients. When the
	// provider advertises a registration_endpoint, dynamic registration runs and
	// the server-assigned secret supersedes this value.
	ClientSecret string

	// CallbackURL is the registered redirect URI for the authorization code flow.
	CallbackURL string

	// WebauthURL is the base URL of the auth server (e.g. "https://auth.example.com").
	// Used for LoginURL/LogoutURL construction. Derived from IssuerURL if empty.
	WebauthURL string

	// HTTPClient overrides the default HTTP client for OIDC discovery, JWKS
	// fetches, and token exchange requests.
	HTTPClient *http.Client

	// Logf receives diagnostic messages from [NewLazy]'s background discovery
	// retries. Nil disables logging.
	Logf func(format string, args ...any)
}

// Client is an OIDC relying party that performs authorization code flows with
// PKCE and validates JWTs using keys from the provider's JWKS endpoint.
//
// Discovery, JWKS caching, and signature verification are handled by
// [github.com/coreos/go-oidc/v3]. The authorization code flow is handled by
// [golang.org/x/oauth2].
type Client struct {
	cfg  Config
	logf func(format string, args ...any)

	// state holds everything derived from provider discovery (and dynamic
	// registration). [New] populates it before returning; [NewLazy] leaves it
	// nil and a background goroutine stores it when discovery first succeeds.
	// Token operations fail with [ErrNotReady] while it is nil.
	state atomic.Pointer[providerState]
}

// providerState is the discovery-derived half of a Client, swapped in
// atomically once the provider has been reached.
type providerState struct {
	provider       *oidc.Provider
	oauth2Cfg      oauth2.Config
	idVerifier     *oidc.IDTokenVerifier // audience = ClientID (for ID tokens at callback)
	accessVerifier *oidc.IDTokenVerifier // skip audience check (for access tokens per-request)
	clientID       string                // server-assigned by dynamic registration, else Config.ClientID
}

// Lazy retry backoff bounds; see retryConnect.
const (
	lazyInitialBackoff = time.Second
	lazyMaxBackoff     = time.Minute
)

// New creates a Client by performing OIDC discovery against the configured
// IssuerURL. Returns an error if discovery fails or the configuration is
// incomplete. Use [NewLazy] when the application must boot even while the
// provider is unreachable.
func New(ctx context.Context, cfg Config) (*Client, error) {
	c, err := newClient(cfg)
	if err != nil {
		return nil, err
	}
	st, err := c.connect(ctx)
	if err != nil {
		return nil, err
	}
	c.state.Store(st)
	return c, nil
}

// NewLazy creates a Client without contacting the provider. Discovery (and
// dynamic registration) run in a background goroutine, retrying with
// exponential backoff until they succeed or ctx is cancelled, so an
// unavailable IdP degrades sign-in instead of blocking application startup.
//
// Until the first success, Ready reports false, token operations return
// [ErrNotReady], AuthorizeURL returns "", and CallbackHandler responds 503.
// The error return covers static misconfiguration only.
//
// ctx must outlive the Client: it bounds both the retry loop and the
// provider's later JWKS fetches.
func NewLazy(ctx context.Context, cfg Config) (*Client, error) {
	return newLazy(ctx, cfg, lazyInitialBackoff, lazyMaxBackoff)
}

// newLazy is NewLazy with injectable backoff bounds for tests.
func newLazy(ctx context.Context, cfg Config, initial, max time.Duration) (*Client, error) {
	c, err := newClient(cfg)
	if err != nil {
		return nil, err
	}
	go c.retryConnect(ctx, initial, max)
	return c, nil
}

// newClient validates static configuration and builds the connection-free
// half of a Client.
func newClient(cfg Config) (*Client, error) {
	if cfg.IssuerURL == "" {
		return nil, fmt.Errorf("oidclient: IssuerURL is required")
	}

	if cfg.WebauthURL == "" {
		u, err := url.Parse(cfg.IssuerURL)
		if err == nil {
			cfg.WebauthURL = u.Scheme + "://" + u.Host
		}
	}

	logf := cfg.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Client{cfg: cfg, logf: logf}, nil
}

// connect performs discovery and dynamic registration, returning the derived
// provider state. It does not mutate the Client.
func (c *Client) connect(ctx context.Context) (*providerState, error) {
	// Use custom HTTP client if provided.
	provCtx := ctx
	if c.cfg.HTTPClient != nil {
		provCtx = oidc.ClientContext(ctx, c.cfg.HTTPClient)
	}

	provider, err := oidc.NewProvider(provCtx, c.cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidclient: discovery failed: %w", err)
	}

	// Auto-register via RFC 7591 if the provider advertises a registration
	// endpoint and the caller supplied a CallbackURL. The server-assigned
	// client_id (and client_secret, if any) supersedes Config.ClientID for
	// all subsequent operations: token exchange, ID-token audience checks,
	// and any consumer that reads Client.ClientID.
	// A static confidential client supplies its secret up front; dynamic
	// registration (below) supersedes it when the provider supports RFC 7591.
	clientID := c.cfg.ClientID
	clientSecret := c.cfg.ClientSecret
	if c.cfg.CallbackURL != "" {
		var meta struct {
			RegistrationEndpoint string `json:"registration_endpoint"`
		}
		if err := provider.Claims(&meta); err == nil && meta.RegistrationEndpoint != "" {
			info, err := autoRegister(provCtx, meta.RegistrationEndpoint, c.cfg.ClientName, c.cfg.CallbackURL, c.cfg.HTTPClient)
			if err != nil {
				return nil, fmt.Errorf("oidclient: auto-registration failed: %w", err)
			}
			clientID = info.ClientID
			clientSecret = info.ClientSecret
		}
	}

	// Explicitly set AuthStyleInParams: client_id (and, for a confidential
	// client, client_secret) go in the token-request form body per RFC 6749
	// §2.3.1. Leaving AuthStyle as Unknown causes the oauth2 library to probe
	// with Basic auth first, which can consume single-use auth codes on
	// providers that delete before validating client_id. Google accepts the
	// secret in the body, so this style serves both public and confidential
	// clients.
	endpoint := provider.Endpoint()
	endpoint.AuthStyle = oauth2.AuthStyleInParams

	oauth2Cfg := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     endpoint,
		RedirectURL:  c.cfg.CallbackURL,
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}

	// ID token verifier: checks audience = ClientID.
	idVerifier := provider.Verifier(&oidc.Config{
		ClientID: clientID,
	})

	// Access token verifier: skips audience check because webauth access
	// tokens don't carry an aud claim matching the client ID.
	accessVerifier := provider.Verifier(&oidc.Config{
		SkipClientIDCheck: true,
	})

	return &providerState{
		provider:       provider,
		oauth2Cfg:      oauth2Cfg,
		idVerifier:     idVerifier,
		accessVerifier: accessVerifier,
		clientID:       clientID,
	}, nil
}

// retryConnect drives a lazy client to readiness: connect with exponential
// backoff until success or ctx cancellation. The goroutine exits either way.
func (c *Client) retryConnect(ctx context.Context, initial, max time.Duration) {
	backoff := initial
	for {
		st, err := c.connect(ctx)
		if err == nil {
			c.state.Store(st)
			c.logf("oidclient: provider ready: %s", c.cfg.IssuerURL)
			return
		}
		c.logf("oidclient: provider unavailable (retry in %s): %v", backoff, err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, max)
	}
}

// Ready reports whether provider discovery has completed. A client from [New]
// is always ready; a client from [NewLazy] becomes ready when the background
// retry first succeeds. While false, token operations return [ErrNotReady].
func (c *Client) Ready() bool { return c.state.Load() != nil }

// CookieName returns the configured session cookie name.
func (c *Client) CookieName() string { return c.cfg.CookieName }

// ClientID returns the OIDC client ID in effect for this Client. When the
// provider supports RFC 7591 dynamic registration, this is the server-assigned
// id (which may differ from Config.ClientID); otherwise it is the pre-registered
// id from Config. On a not-yet-ready lazy client it is the Config value.
func (c *Client) ClientID() string {
	if st := c.state.Load(); st != nil && st.clientID != "" {
		return st.clientID
	}
	return c.cfg.ClientID
}

// FlowConfigured reports whether the OIDC authorization code flow is configured
// (i.e., ClientID and CallbackURL are set).
func (c *Client) FlowConfigured() bool {
	return c.ClientID() != "" && c.cfg.CallbackURL != ""
}

// AuthorizeURL builds the OIDC authorization URL with PKCE.
// verifier is the PKCE code verifier (store it for the callback); the S256
// challenge is computed automatically. Returns "" while a lazy client is not
// ready (the endpoints are unknown before discovery) — check [Client.Ready]
// before starting a flow.
func (c *Client) AuthorizeURL(state, verifier string) string {
	st := c.state.Load()
	if st == nil {
		return ""
	}
	return st.oauth2Cfg.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))
}

// RegisterURL builds the URL to the IdP's registration page with the OIDC
// parameters needed to complete an authorization code flow after signup.
// The verifier is the same PKCE code verifier used with ExchangeCode.
// After registration, the IdP redirects to CallbackURL with an authorization
// code, identical to the login flow.
func (c *Client) RegisterURL(state, verifier string) string {
	u, err := url.Parse(c.cfg.IssuerURL + "/register")
	if err != nil {
		return c.cfg.IssuerURL + "/register"
	}
	q := u.Query()
	q.Set("client_id", c.ClientID())
	q.Set("redirect_uri", c.cfg.CallbackURL)
	q.Set("scope", "openid email profile")
	q.Set("state", state)
	q.Set("code_challenge", s256Challenge(verifier))
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return u.String()
}

// s256Challenge computes the S256 PKCE code challenge from a verifier.
func s256Challenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// ExchangeCode exchanges an authorization code for tokens using the PKCE
// verifier. Returns the access token (for session storage) and the verified
// claims from the ID token.
func (c *Client) ExchangeCode(ctx context.Context, code, verifier string) (accessToken string, claims *Claims, err error) {
	st := c.state.Load()
	if st == nil {
		return "", nil, ErrNotReady
	}
	if c.cfg.HTTPClient != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, c.cfg.HTTPClient)
	}

	tok, err := st.oauth2Cfg.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return "", nil, fmt.Errorf("token exchange: %w", err)
	}

	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return "", nil, ErrNoIDToken
	}

	idToken, err := st.idVerifier.Verify(ctx, rawIDToken)
	if err != nil {
		return "", nil, fmt.Errorf("verify ID token: %w", err)
	}

	var cl Claims
	if err := idToken.Claims(&cl); err != nil {
		return "", nil, fmt.Errorf("extract claims: %w", err)
	}
	if cl.Sub == "" {
		return "", nil, ErrMissingSub
	}

	return tok.AccessToken, &cl, nil
}

// ValidateCookie extracts the JWT from the session cookie and validates it.
// Returns ErrNoCookie if the cookie is absent.
func (c *Client) ValidateCookie(r *http.Request) (*Claims, error) {
	cookie, err := r.Cookie(c.cfg.CookieName)
	if err != nil {
		return nil, ErrNoCookie
	}
	return c.Validate(r.Context(), cookie.Value)
}

// Validate parses and validates a raw access token JWT, returning the
// extracted claims. The token's signature is verified against the provider's
// JWKS, and standard claims (issuer, expiry) are checked. Returns
// [ErrNotReady] while a lazy client's discovery is pending — treat it as an
// unauthenticated request.
func (c *Client) Validate(ctx context.Context, tokenStr string) (*Claims, error) {
	st := c.state.Load()
	if st == nil {
		return nil, ErrNotReady
	}
	tok, err := st.accessVerifier.Verify(ctx, tokenStr)
	if err != nil {
		return nil, fmt.Errorf("oidclient: invalid token: %w", err)
	}

	var cl Claims
	if err := tok.Claims(&cl); err != nil {
		return nil, fmt.Errorf("oidclient: extract claims: %w", err)
	}
	if cl.Sub == "" {
		return nil, ErrMissingSub
	}
	return &cl, nil
}

// LoginURL returns a URL to redirect unauthenticated users to the IdP login.
func (c *Client) LoginURL(redirectPath string) string {
	base := c.cfg.WebauthURL + "/login"
	if redirectPath == "" {
		return base
	}
	u, err := url.Parse(base)
	if err != nil {
		return base
	}
	q := u.Query()
	q.Set("redirect_uri", redirectPath)
	u.RawQuery = q.Encode()
	return u.String()
}

// LogoutURL returns the IdP logout URL.
func (c *Client) LogoutURL() string {
	return c.cfg.WebauthURL + "/logout"
}
