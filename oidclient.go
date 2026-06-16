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
	ErrNoCookie       = errors.New("oidclient: missing auth cookie")
	ErrNoIDToken      = errors.New("oidclient: token response missing id_token")
	ErrMissingSub     = errors.New("oidclient: token missing sub claim")
	ErrNoRefreshToken = errors.New("oidclient: no refresh token")

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

	// Exp is the token's expiry as a Unix timestamp (the JWT "exp" claim).
	// Callers can use it to renew proactively -- via Refresh, before a request
	// fails -- rather than reacting to a validation failure. Zero if the token
	// carried no exp.
	Exp int64 `json:"exp,omitempty"`
}

// ExpiresAt returns the token expiry as a time.Time, or the zero time if the
// token carried no exp claim.
func (c *Claims) ExpiresAt() time.Time {
	if c.Exp == 0 {
		return time.Time{}
	}
	return time.Unix(c.Exp, 0)
}

// Tokens holds the credentials returned by a successful code exchange
// ([Client.Exchange]) or renewal ([Client.Refresh]).
//
// RefreshToken is empty unless the IdP granted offline access (see
// [Config.OfflineAccess]). On an IdP that rotates refresh tokens -- as webauth
// does, with replay detection -- each Exchange/Refresh returns a *new*
// RefreshToken and the caller MUST persist it, discarding the one just used;
// reusing a rotated token trips replay detection and ends the session.
type Tokens struct {
	AccessToken  string
	RefreshToken string
	Expiry       time.Time
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

	// OfflineAccess requests the "offline_access" scope so the IdP issues a
	// refresh token, enabling session renewal via [Client.Refresh] without an
	// interactive redirect. Leave false for short-lived sessions: a refresh
	// token is a long-lived, high-value credential and a relying party that
	// does not renew sessions should not request one. webauth gates refresh
	// issuance on this scope; for Google, prefer a confidential client (offline
	// issuance there keys off access_type, which this scope does not set).
	OfflineAccess bool

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
	endSessionURL  string                // discovered end_session_endpoint (RP-initiated logout); "" if unadvertised
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

	// Pull the RP-initiated-logout endpoint from discovery. Optional: many
	// providers don't advertise it, in which case LogoutURL falls back to the
	// legacy WebauthURL/logout path. Claims only errors if the doc is
	// unparseable, which NewProvider already would have rejected.
	var logoutMeta struct {
		EndSessionEndpoint string `json:"end_session_endpoint"`
	}
	_ = provider.Claims(&logoutMeta)

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

	scopes := []string{oidc.ScopeOpenID, "email", "profile"}
	if c.cfg.OfflineAccess {
		scopes = append(scopes, oidc.ScopeOfflineAccess)
	}

	oauth2Cfg := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     endpoint,
		RedirectURL:  c.cfg.CallbackURL,
		Scopes:       scopes,
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
		endSessionURL:  logoutMeta.EndSessionEndpoint,
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

// Exchange exchanges an authorization code for tokens using the PKCE verifier.
// It returns the [Tokens] (access token, refresh token when offline access was
// granted, and access-token expiry) along with the verified claims from the ID
// token. Persist Tokens.RefreshToken to renew the session later via
// [Client.Refresh]; on a rotating IdP it must be stored, not the request-time
// token.
func (c *Client) Exchange(ctx context.Context, code, verifier string) (*Tokens, *Claims, error) {
	st := c.state.Load()
	if st == nil {
		return nil, nil, ErrNotReady
	}
	if c.cfg.HTTPClient != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, c.cfg.HTTPClient)
	}

	tok, err := st.oauth2Cfg.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, nil, fmt.Errorf("token exchange: %w", err)
	}

	// The initial code exchange must yield an ID token: it is the verified
	// assertion of who just authenticated.
	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, nil, ErrNoIDToken
	}
	claims, err := st.verifyIDClaims(ctx, rawIDToken)
	if err != nil {
		return nil, nil, err
	}
	return tokensFrom(tok), claims, nil
}

// ExchangeCode exchanges an authorization code for tokens using the PKCE
// verifier, returning the access token (for session storage) and the verified
// claims from the ID token.
//
// Deprecated: use [Client.Exchange], which additionally returns the refresh
// token needed to renew the session via [Client.Refresh] and the access-token
// expiry. ExchangeCode discards both.
func (c *Client) ExchangeCode(ctx context.Context, code, verifier string) (accessToken string, claims *Claims, err error) {
	toks, cl, err := c.Exchange(ctx, code, verifier)
	if err != nil {
		return "", nil, err
	}
	return toks.AccessToken, cl, nil
}

// Refresh renews a session using a refresh token obtained from [Client.Exchange]
// (which requires [Config.OfflineAccess]). It POSTs grant_type=refresh_token to
// the provider's token endpoint and returns the new [Tokens] and verified
// claims.
//
// On an IdP that rotates refresh tokens -- as webauth does -- the returned
// Tokens.RefreshToken is a NEW token: persist it and discard the one passed in.
// The caller is responsible for storing the rotated token (oidclient keeps no
// session state); failing to do so ends the session on the next refresh.
//
// Returns [ErrNoRefreshToken] for an empty token and [ErrNotReady] while a lazy
// client's discovery is pending.
func (c *Client) Refresh(ctx context.Context, refreshToken string) (*Tokens, *Claims, error) {
	st := c.state.Load()
	if st == nil {
		return nil, nil, ErrNotReady
	}
	if refreshToken == "" {
		return nil, nil, ErrNoRefreshToken
	}
	if c.cfg.HTTPClient != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, c.cfg.HTTPClient)
	}

	// A token with only a refresh token is invalid, so TokenSource performs the
	// refresh grant. oauth2 carries the rotated refresh token through on the
	// result, falling back to the supplied one only when the response omits it.
	tok, err := st.oauth2Cfg.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken}).Token()
	if err != nil {
		return nil, nil, fmt.Errorf("refresh token: %w", err)
	}

	// A refresh response MAY omit the ID token (OIDC Core 12.2). Prefer the
	// fresh ID token when present; otherwise fall back to the access token,
	// which webauth issues as a verifiable JWT.
	var claims *Claims
	if raw, ok := tok.Extra("id_token").(string); ok && raw != "" {
		claims, err = st.verifyIDClaims(ctx, raw)
	} else {
		claims, err = c.Validate(ctx, tok.AccessToken)
	}
	if err != nil {
		return nil, nil, err
	}
	return tokensFrom(tok), claims, nil
}

// tokensFrom projects an oauth2 token onto the public [Tokens] view.
func tokensFrom(tok *oauth2.Token) *Tokens {
	return &Tokens{
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		Expiry:       tok.Expiry,
	}
}

// verifyIDClaims verifies a raw ID token against the audience-checked verifier
// and extracts its claims, enforcing a non-empty sub.
func (st *providerState) verifyIDClaims(ctx context.Context, rawIDToken string) (*Claims, error) {
	idToken, err := st.idVerifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("verify ID token: %w", err)
	}
	var cl Claims
	if err := idToken.Claims(&cl); err != nil {
		return nil, fmt.Errorf("extract claims: %w", err)
	}
	if cl.Sub == "" {
		return nil, ErrMissingSub
	}
	return &cl, nil
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

// LogoutURL returns the IdP logout URL. When the provider advertises an
// end_session_endpoint (OIDC RP-Initiated Logout), that discovered, fully
// qualified URL is returned -- it is issuer/tenant-scoped and actually exists.
// Only when no such endpoint is advertised (or discovery has not completed) does
// this fall back to the legacy WebauthURL/logout path, which historically was a
// fabricated guess and may 404 on providers that do not serve it.
func (c *Client) LogoutURL() string {
	if st := c.state.Load(); st != nil && st.endSessionURL != "" {
		return st.endSessionURL
	}
	return c.cfg.WebauthURL + "/logout"
}
