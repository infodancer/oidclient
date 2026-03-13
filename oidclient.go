// Package oidclient is an OIDC relying party library for web applications
// authenticating against an OpenID Connect provider (designed for use with
// infodancer/webauth but compatible with any spec-compliant IdP).
//
// It handles OIDC discovery, JWKS fetching with caching, RS256 JWT validation,
// PKCE authorization flows, and token exchange.
package oidclient

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Sentinel errors returned by Validate and ValidateCookie.
var (
	ErrNoCookie       = errors.New("oidclient: missing auth cookie")
	ErrTokenInvalid   = errors.New("oidclient: invalid token")
	ErrTokenExpired   = errors.New("oidclient: token expired")
	ErrIssuerMismatch = errors.New("oidclient: issuer mismatch")
	ErrMissingSub     = errors.New("oidclient: token missing sub claim")
	ErrKeyNotFound    = errors.New("oidclient: public key not found")
)

// Claims holds the JWT claims extracted from an access or ID token.
type Claims struct {
	Sub   string
	Email string
	Name  string
	Roles []string
}

// Config configures the OIDC client.
type Config struct {
	// IssuerURL is the OIDC issuer (e.g. "https://auth.example.com/t/mytenant").
	// When set, the discovery document at IssuerURL+"/.well-known/openid-configuration"
	// is fetched to auto-populate JWKSEndpoint, authorize, and token endpoints.
	IssuerURL string

	// Issuer is the expected "iss" claim value. If empty the issuer check is skipped.
	Issuer string

	// CookieName is the name of the HttpOnly cookie storing the JWT session token.
	CookieName string

	// ClientID is this application's registered OIDC client ID.
	ClientID string

	// CallbackURL is the registered redirect URI for the authorization code flow.
	CallbackURL string

	// WebauthURL is the base URL of the auth server (e.g. "https://auth.example.com").
	// Derived from IssuerURL if empty.
	WebauthURL string

	// JWKSEndpoint overrides the JWKS URL from autodiscovery.
	JWKSEndpoint string

	// PEMKeyPath is a path to an RSA public key PEM file (development fallback).
	PEMKeyPath string

	// TenantID is used to construct OIDC endpoints when IssuerURL is not set.
	TenantID string

	// HTTPClient overrides the default HTTP client (10s timeout) for JWKS/token requests.
	HTTPClient *http.Client
}

// Client is an OIDC relying party that validates JWTs and performs authorization code flows.
// Keys are cached in memory and refreshed from JWKS on kid-miss or TTL expiry.
type Client struct {
	cfg        Config
	httpClient *http.Client

	mu            sync.RWMutex
	keys          map[string]*rsa.PublicKey
	keysFetchedAt time.Time
	keysTTL       time.Duration

	// Populated by OIDC autodiscovery.
	discoveredAuthorizeURL string
	discoveredTokenURL     string
}

// New creates a Client and eagerly loads public keys.
// Returns an error if the key source is misconfigured or unreachable.
func New(cfg Config) (*Client, error) {
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	c := &Client{
		cfg:        cfg,
		httpClient: httpClient,
		keys:       make(map[string]*rsa.PublicKey),
		keysTTL:    time.Hour,
	}
	if cfg.IssuerURL != "" {
		if err := c.fetchDiscovery(); err != nil {
			return nil, err
		}
	}
	if c.cfg.JWKSEndpoint == "" && c.cfg.PEMKeyPath == "" {
		return nil, fmt.Errorf("oidclient: one of JWKSEndpoint or PEMKeyPath must be set (or set IssuerURL for autodiscovery)")
	}
	if err := c.loadKeys(); err != nil {
		return nil, err
	}
	return c, nil
}

// CookieName returns the configured session cookie name.
func (c *Client) CookieName() string { return c.cfg.CookieName }

// FlowConfigured reports whether the OIDC authorization code flow is configured.
func (c *Client) FlowConfigured() bool {
	if c.cfg.ClientID == "" || c.cfg.CallbackURL == "" {
		return false
	}
	return c.discoveredAuthorizeURL != "" || c.cfg.TenantID != ""
}

// AuthorizeURL builds the OIDC authorization URL with PKCE parameters.
// state is an opaque CSRF nonce; challenge is the S256 PKCE challenge.
func (c *Client) AuthorizeURL(state, challenge string) string {
	base := c.discoveredAuthorizeURL
	if base == "" {
		base = fmt.Sprintf("%s/t/%s/authorize", c.cfg.WebauthURL, c.cfg.TenantID)
	}
	u, _ := url.Parse(base)
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", c.cfg.ClientID)
	q.Set("redirect_uri", c.cfg.CallbackURL)
	q.Set("scope", "openid email profile")
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("state", state)
	u.RawQuery = q.Encode()
	return u.String()
}

// ExchangeCode exchanges an authorization code for an access token.
// verifier is the PKCE code_verifier used to derive the challenge.
// Only the access_token is returned; the id_token and refresh_token from the
// token response are intentionally discarded — the access token JWT is used
// directly as the session credential.
func (c *Client) ExchangeCode(ctx context.Context, code, verifier string) (string, error) {
	tokenURL := c.discoveredTokenURL
	if tokenURL == "" {
		tokenURL = fmt.Sprintf("%s/t/%s/token", c.cfg.WebauthURL, c.cfg.TenantID)
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {c.cfg.CallbackURL},
		"client_id":     {c.cfg.ClientID},
		"code_verifier": {verifier},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned %d", resp.StatusCode)
	}

	var body struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}
	if body.AccessToken == "" {
		return "", fmt.Errorf("token response missing access_token")
	}
	return body.AccessToken, nil
}

// ValidateCookie extracts the JWT from the session cookie and validates it.
// Returns ErrNoCookie if the cookie is absent.
func (c *Client) ValidateCookie(r *http.Request) (*Claims, error) {
	cookie, err := r.Cookie(c.cfg.CookieName)
	if err != nil {
		return nil, ErrNoCookie
	}
	return c.Validate(cookie.Value)
}

// Validate parses and validates a raw JWT string, returning extracted claims.
// Returns ErrTokenInvalid, ErrTokenExpired, ErrIssuerMismatch, or ErrMissingSub
// on the corresponding failure conditions.
func (c *Client) Validate(tokenStr string) (*Claims, error) {
	tok, err := jwt.Parse(tokenStr, c.keyFunc, jwt.WithExpirationRequired())
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, fmt.Errorf("%w: %w", ErrTokenExpired, err)
		}
		return nil, fmt.Errorf("%w: %w", ErrTokenInvalid, err)
	}

	mapClaims, ok := tok.Claims.(jwt.MapClaims)
	if !ok || !tok.Valid {
		return nil, ErrTokenInvalid
	}

	if c.cfg.Issuer != "" {
		iss, _ := mapClaims["iss"].(string)
		if iss != c.cfg.Issuer {
			return nil, fmt.Errorf("%w: got %q, want %q", ErrIssuerMismatch, iss, c.cfg.Issuer)
		}
	}

	claims := &Claims{
		Sub:   stringClaim(mapClaims, "sub"),
		Email: stringClaim(mapClaims, "email"),
		Name:  stringClaim(mapClaims, "name"),
		Roles: stringSliceClaim(mapClaims, "roles"),
	}
	if claims.Sub == "" {
		return nil, ErrMissingSub
	}
	return claims, nil
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

// --- key management ---

func (c *Client) keyFunc(token *jwt.Token) (any, error) {
	if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}
	kid, _ := token.Header["kid"].(string)

	c.mu.RLock()
	key, ok := c.findKey(kid)
	expired := c.cfg.JWKSEndpoint != "" && time.Since(c.keysFetchedAt) > c.keysTTL
	c.mu.RUnlock()

	if ok && !expired {
		return key, nil
	}

	if c.cfg.JWKSEndpoint != "" {
		c.mu.Lock()
		if key, ok = c.findKey(kid); !ok || expired {
			_ = c.fetchJWKS()
			key, ok = c.findKey(kid)
		}
		c.mu.Unlock()
		if ok {
			return key, nil
		}
	}

	return nil, fmt.Errorf("%w: kid %q", ErrKeyNotFound, kid)
}

func (c *Client) findKey(kid string) (*rsa.PublicKey, bool) {
	if kid != "" {
		key, ok := c.keys[kid]
		return key, ok
	}
	for _, key := range c.keys {
		return key, true
	}
	return nil, false
}

func (c *Client) fetchDiscovery() error {
	discoveryURL := strings.TrimRight(c.cfg.IssuerURL, "/") + "/.well-known/openid-configuration"
	resp, err := c.httpClient.Get(discoveryURL) //nolint:noctx
	if err != nil {
		return fmt.Errorf("fetch OIDC discovery: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("OIDC discovery returned %d", resp.StatusCode)
	}

	var doc struct {
		JWKSURI      string `json:"jwks_uri"`
		AuthorizeURL string `json:"authorization_endpoint"`
		TokenURL     string `json:"token_endpoint"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return fmt.Errorf("parse OIDC discovery: %w", err)
	}
	if doc.JWKSURI == "" || doc.AuthorizeURL == "" || doc.TokenURL == "" {
		return fmt.Errorf("OIDC discovery document missing required fields")
	}

	if c.cfg.JWKSEndpoint == "" {
		c.cfg.JWKSEndpoint = doc.JWKSURI
	}
	c.discoveredAuthorizeURL = doc.AuthorizeURL
	c.discoveredTokenURL = doc.TokenURL

	if c.cfg.WebauthURL == "" {
		u, err := url.Parse(c.cfg.IssuerURL)
		if err == nil {
			c.cfg.WebauthURL = u.Scheme + "://" + u.Host
		}
	}
	return nil
}

func (c *Client) loadKeys() error {
	if c.cfg.JWKSEndpoint != "" {
		return c.fetchJWKS()
	}
	return c.loadPEM()
}

func (c *Client) fetchJWKS() error {
	resp, err := c.httpClient.Get(c.cfg.JWKSEndpoint) //nolint:noctx
	if err != nil {
		return fmt.Errorf("fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	var doc struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return fmt.Errorf("parse JWKS: %w", err)
	}

	newKeys := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kty != "RSA" {
			continue
		}
		key, err := rsaKeyFromJWK(k.N, k.E)
		if err != nil {
			continue
		}
		newKeys[k.Kid] = key
	}
	if len(newKeys) == 0 {
		return fmt.Errorf("JWKS contained no usable RSA keys")
	}
	c.keys = newKeys
	c.keysFetchedAt = time.Now()
	return nil
}

func (c *Client) loadPEM() error {
	data, err := os.ReadFile(c.cfg.PEMKeyPath)
	if err != nil {
		return fmt.Errorf("read public key file: %w", err)
	}
	key, err := jwt.ParseRSAPublicKeyFromPEM(data)
	if err != nil {
		return fmt.Errorf("parse RSA public key PEM: %w", err)
	}
	c.keys[""] = key
	return nil
}

// --- helpers ---

func rsaKeyFromJWK(nB64, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, fmt.Errorf("decode JWK n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, fmt.Errorf("decode JWK e: %w", err)
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}, nil
}

func stringClaim(claims jwt.MapClaims, key string) string {
	v, _ := claims[key].(string)
	return v
}

func stringSliceClaim(claims jwt.MapClaims, key string) []string {
	raw, ok := claims[key]
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case []string:
		return v
	case []interface{}:
		result := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}
