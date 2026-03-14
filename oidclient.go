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
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Sentinel errors returned by Validate, ValidateCookie, and ExchangeCode.
var (
	ErrNoCookie   = errors.New("oidclient: missing auth cookie")
	ErrNoIDToken  = errors.New("oidclient: token response missing id_token")
	ErrMissingSub = errors.New("oidclient: token missing sub claim")
)

// Claims holds the JWT claims extracted from an ID or access token.
type Claims struct {
	Sub   string   `json:"sub"`
	Email string   `json:"email"`
	Name  string   `json:"name"`
	Roles []string `json:"roles,omitempty"`
}

// Config configures the OIDC client.
type Config struct {
	// IssuerURL is the OIDC issuer (e.g. "https://auth.example.com/t/mytenant").
	// Used for discovery and token verification. Required.
	IssuerURL string

	// CookieName is the name of the HttpOnly cookie storing the JWT session token.
	CookieName string

	// ClientID is this application's registered OIDC client ID.
	ClientID string

	// CallbackURL is the registered redirect URI for the authorization code flow.
	CallbackURL string

	// WebauthURL is the base URL of the auth server (e.g. "https://auth.example.com").
	// Used for LoginURL/LogoutURL construction. Derived from IssuerURL if empty.
	WebauthURL string

	// HTTPClient overrides the default HTTP client for OIDC discovery, JWKS
	// fetches, and token exchange requests.
	HTTPClient *http.Client
}

// Client is an OIDC relying party that performs authorization code flows with
// PKCE and validates JWTs using keys from the provider's JWKS endpoint.
//
// Discovery, JWKS caching, and signature verification are handled by
// [github.com/coreos/go-oidc/v3]. The authorization code flow is handled by
// [golang.org/x/oauth2].
type Client struct {
	cfg Config

	provider       *oidc.Provider
	oauth2Cfg      oauth2.Config
	idVerifier     *oidc.IDTokenVerifier // audience = ClientID (for ID tokens at callback)
	accessVerifier *oidc.IDTokenVerifier // skip audience check (for access tokens per-request)
}

// New creates a Client by performing OIDC discovery against the configured
// IssuerURL. Returns an error if discovery fails or the configuration is
// incomplete.
func New(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.IssuerURL == "" {
		return nil, fmt.Errorf("oidclient: IssuerURL is required")
	}

	if cfg.WebauthURL == "" {
		u, err := url.Parse(cfg.IssuerURL)
		if err == nil {
			cfg.WebauthURL = u.Scheme + "://" + u.Host
		}
	}

	// Use custom HTTP client if provided.
	provCtx := ctx
	if cfg.HTTPClient != nil {
		provCtx = oidc.ClientContext(ctx, cfg.HTTPClient)
	}

	provider, err := oidc.NewProvider(provCtx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidclient: discovery failed: %w", err)
	}

	// Explicitly set AuthStyleInParams: public PKCE clients send client_id
	// in the form body per RFC 6749 §2.3.  Leaving AuthStyle as Unknown
	// causes the oauth2 library to probe with Basic auth first, which can
	// consume single-use auth codes on providers that delete before
	// validating client_id.
	endpoint := provider.Endpoint()
	endpoint.AuthStyle = oauth2.AuthStyleInParams

	oauth2Cfg := oauth2.Config{
		ClientID:    cfg.ClientID,
		Endpoint:    endpoint,
		RedirectURL: cfg.CallbackURL,
		Scopes:      []string{oidc.ScopeOpenID, "email", "profile"},
	}

	// ID token verifier: checks audience = ClientID.
	idVerifier := provider.Verifier(&oidc.Config{
		ClientID: cfg.ClientID,
	})

	// Access token verifier: skips audience check because webauth access
	// tokens don't carry an aud claim matching the client ID.
	accessVerifier := provider.Verifier(&oidc.Config{
		SkipClientIDCheck: true,
	})

	return &Client{
		cfg:            cfg,
		provider:       provider,
		oauth2Cfg:      oauth2Cfg,
		idVerifier:     idVerifier,
		accessVerifier: accessVerifier,
	}, nil
}

// CookieName returns the configured session cookie name.
func (c *Client) CookieName() string { return c.cfg.CookieName }

// FlowConfigured reports whether the OIDC authorization code flow is configured
// (i.e., ClientID and CallbackURL are set).
func (c *Client) FlowConfigured() bool {
	return c.cfg.ClientID != "" && c.cfg.CallbackURL != ""
}

// AuthorizeURL builds the OIDC authorization URL with PKCE.
// verifier is the PKCE code verifier (store it for the callback); the S256
// challenge is computed automatically.
func (c *Client) AuthorizeURL(state, verifier string) string {
	return c.oauth2Cfg.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))
}

// ExchangeCode exchanges an authorization code for tokens using the PKCE
// verifier. Returns the access token (for session storage) and the verified
// claims from the ID token.
func (c *Client) ExchangeCode(ctx context.Context, code, verifier string) (accessToken string, claims *Claims, err error) {
	if c.cfg.HTTPClient != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, c.cfg.HTTPClient)
	}

	tok, err := c.oauth2Cfg.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return "", nil, fmt.Errorf("token exchange: %w", err)
	}

	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return "", nil, ErrNoIDToken
	}

	idToken, err := c.idVerifier.Verify(ctx, rawIDToken)
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
// JWKS, and standard claims (issuer, expiry) are checked.
func (c *Client) Validate(ctx context.Context, tokenStr string) (*Claims, error) {
	tok, err := c.accessVerifier.Verify(ctx, tokenStr)
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
