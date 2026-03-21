package oidclient

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jwtgo "github.com/golang-jwt/jwt/v5"
)

// testKeyPair generates an RSA key pair for testing.
func testKeyPair(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return priv, &priv.PublicKey
}

// fakeProvider starts an httptest.Server that serves OIDC discovery, JWKS,
// and a token endpoint. Returns the server and a function to issue test JWTs.
func fakeProvider(t *testing.T) (srv *httptest.Server, issuer string, issueToken func(sub, email string, ttl time.Duration) string) {
	t.Helper()
	priv, pub := testKeyPair(t)
	kid := "test-kid"

	mux := http.NewServeMux()

	// We need the server URL in handlers, so use a pointer that's set after Start.
	var baseURL string

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		base := baseURL
		doc := map[string]any{
			"issuer":                                base,
			"authorization_endpoint":                base + "/authorize",
			"token_endpoint":                        base + "/token",
			"jwks_uri":                              base + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	})

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		doc := map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA",
				"kid": kid,
				"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
				"alg": "RS256",
				"use": "sig",
			}},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		// Issue both access_token and id_token for the test.
		now := time.Now()
		accessClaims := jwtgo.MapClaims{
			"iss":   baseURL,
			"sub":   "user-from-token",
			"email": "token@example.com",
			"name":  "Token User",
			"roles": []string{"user"},
			"iat":   now.Unix(),
			"exp":   now.Add(time.Hour).Unix(),
		}
		accessTok := jwtgo.NewWithClaims(jwtgo.SigningMethodRS256, accessClaims)
		accessTok.Header["kid"] = kid
		accessSigned, _ := accessTok.SignedString(priv)

		idClaims := jwtgo.MapClaims{
			"iss":   baseURL,
			"sub":   "user-from-token",
			"aud":   "test-client",
			"email": "token@example.com",
			"name":  "Token User",
			"roles": []string{"user"},
			"iat":   now.Unix(),
			"exp":   now.Add(time.Hour).Unix(),
		}
		idTok := jwtgo.NewWithClaims(jwtgo.SigningMethodRS256, idClaims)
		idTok.Header["kid"] = kid
		idSigned, _ := idTok.SignedString(priv)

		resp := map[string]any{
			"access_token": accessSigned,
			"id_token":     idSigned,
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	srv = httptest.NewServer(mux)
	baseURL = srv.URL
	t.Cleanup(srv.Close)

	issueToken = func(sub, email string, ttl time.Duration) string {
		now := time.Now()
		claims := jwtgo.MapClaims{
			"iss":   srv.URL,
			"sub":   sub,
			"email": email,
			"name":  "Test User",
			"roles": []string{"user"},
			"iat":   now.Unix(),
			"exp":   now.Add(ttl).Unix(),
		}
		tok := jwtgo.NewWithClaims(jwtgo.SigningMethodRS256, claims)
		tok.Header["kid"] = kid
		signed, err := tok.SignedString(priv)
		if err != nil {
			t.Fatalf("sign token: %v", err)
		}
		return signed
	}

	return srv, srv.URL, issueToken
}

// newTestClient creates a Client against the fake provider.
func newTestClient(t *testing.T, srv *httptest.Server, issuer string) *Client {
	t.Helper()
	c, err := New(context.Background(), Config{
		IssuerURL:   issuer,
		CookieName:  "test_jwt",
		ClientID:    "test-client",
		CallbackURL: srv.URL + "/auth/callback",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestValidate_Success(t *testing.T) {
	srv, issuer, issue := fakeProvider(t)
	c := newTestClient(t, srv, issuer)

	token := issue("user-123", "alice@example.com", time.Hour)

	claims, err := c.Validate(context.Background(), token)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.Sub != "user-123" {
		t.Errorf("sub = %q, want user-123", claims.Sub)
	}
	if claims.Email != "alice@example.com" {
		t.Errorf("email = %q, want alice@example.com", claims.Email)
	}
	if claims.Name != "Test User" {
		t.Errorf("name = %q, want Test User", claims.Name)
	}
	if len(claims.Roles) != 1 || claims.Roles[0] != "user" {
		t.Errorf("roles = %v, want [user]", claims.Roles)
	}
}

func TestValidate_ExpiredToken(t *testing.T) {
	srv, issuer, issue := fakeProvider(t)
	c := newTestClient(t, srv, issuer)

	token := issue("user-1", "a@b.com", -time.Hour)

	_, err := c.Validate(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestValidate_GarbageToken(t *testing.T) {
	srv, issuer, _ := fakeProvider(t)
	c := newTestClient(t, srv, issuer)

	_, err := c.Validate(context.Background(), "not.a.jwt")
	if err == nil {
		t.Fatal("expected error for garbage token")
	}
}

func TestValidateCookie(t *testing.T) {
	srv, issuer, issue := fakeProvider(t)
	c := newTestClient(t, srv, issuer)

	token := issue("user-42", "bob@example.com", time.Hour)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "test_jwt", Value: token})

	claims, err := c.ValidateCookie(req)
	if err != nil {
		t.Fatalf("ValidateCookie: %v", err)
	}
	if claims.Sub != "user-42" {
		t.Errorf("sub = %q, want user-42", claims.Sub)
	}
}

func TestValidateCookie_Missing(t *testing.T) {
	srv, issuer, _ := fakeProvider(t)
	c := newTestClient(t, srv, issuer)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := c.ValidateCookie(req)
	if !errors.Is(err, ErrNoCookie) {
		t.Errorf("expected ErrNoCookie, got %v", err)
	}
}

func TestDiscoveryAndFlowConfigured(t *testing.T) {
	srv, issuer, _ := fakeProvider(t)
	c := newTestClient(t, srv, issuer)

	if !c.FlowConfigured() {
		t.Error("expected FlowConfigured() = true")
	}
}

func TestAuthorizeURL(t *testing.T) {
	srv, issuer, _ := fakeProvider(t)
	c := newTestClient(t, srv, issuer)

	verifier := GenerateVerifier()
	u := c.AuthorizeURL("mystate", verifier)

	if !strings.Contains(u, "response_type=code") {
		t.Errorf("missing response_type in %q", u)
	}
	if !strings.Contains(u, "client_id=test-client") {
		t.Errorf("missing client_id in %q", u)
	}
	if !strings.Contains(u, "code_challenge_method=S256") {
		t.Errorf("missing code_challenge_method in %q", u)
	}
	if !strings.Contains(u, "state=mystate") {
		t.Errorf("missing state in %q", u)
	}
}

func TestExchangeCode(t *testing.T) {
	srv, issuer, _ := fakeProvider(t)
	c := newTestClient(t, srv, issuer)

	// The fake token endpoint always returns tokens regardless of code/verifier.
	accessToken, claims, err := c.ExchangeCode(context.Background(), "fake-code", "fake-verifier")
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if accessToken == "" {
		t.Error("expected non-empty access token")
	}
	if claims == nil {
		t.Fatal("expected non-nil claims")
	}
	if claims.Sub != "user-from-token" {
		t.Errorf("sub = %q, want user-from-token", claims.Sub)
	}
	if claims.Email != "token@example.com" {
		t.Errorf("email = %q, want token@example.com", claims.Email)
	}
}

func TestPKCE(t *testing.T) {
	v1 := GenerateVerifier()
	if len(v1) == 0 {
		t.Fatal("empty verifier")
	}
	v2 := GenerateVerifier()
	if v1 == v2 {
		t.Error("two verifiers should differ")
	}
}

func TestGenerateNonce(t *testing.T) {
	n1, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce: %v", err)
	}
	n2, _ := GenerateNonce()
	if n1 == n2 {
		t.Error("two nonces should differ")
	}
}

func TestFlowCookies(t *testing.T) {
	rr := httptest.NewRecorder()
	SetFlowCookie(rr, CookieVerifier, "v", false)
	SetFlowCookie(rr, CookieState, "s", false)
	SetFlowCookie(rr, CookieRedirect, "/foo", false)

	cookies := rr.Result().Cookies()
	if len(cookies) != 3 {
		t.Fatalf("expected 3 cookies, got %d", len(cookies))
	}
	for _, c := range cookies {
		if !c.HttpOnly {
			t.Errorf("cookie %s should be HttpOnly", c.Name)
		}
		if c.MaxAge != FlowCookieMaxAge {
			t.Errorf("cookie %s MaxAge = %d, want %d", c.Name, c.MaxAge, FlowCookieMaxAge)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: CookieVerifier, Value: "v"})
	if got := FlowCookieValue(req, CookieVerifier); got != "v" {
		t.Errorf("verifier = %q, want v", got)
	}
	if got := FlowCookieValue(req, "nonexistent"); got != "" {
		t.Errorf("nonexistent cookie = %q, want empty", got)
	}
}

func TestSessionCookie(t *testing.T) {
	rr := httptest.NewRecorder()
	SetSessionCookie(rr, "sf_jwt", "token-value", true)

	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	c := cookies[0]
	if c.Name != "sf_jwt" {
		t.Errorf("name = %q", c.Name)
	}
	if !c.HttpOnly || !c.Secure {
		t.Error("session cookie should be HttpOnly and Secure")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Error("session cookie should be SameSiteLax")
	}

	rr2 := httptest.NewRecorder()
	ClearSessionCookie(rr2, "sf_jwt", true)
	cleared := rr2.Result().Cookies()
	if len(cleared) != 1 || cleared[0].MaxAge >= 0 {
		t.Error("expected cleared cookie with negative MaxAge")
	}
}

func TestRegisterURL(t *testing.T) {
	srv, issuer, _ := fakeProvider(t)
	c := newTestClient(t, srv, issuer)

	verifier := GenerateVerifier()
	u := c.RegisterURL("mystate", verifier)

	if !strings.Contains(u, "/register") {
		t.Errorf("RegisterURL() = %q, expected /register path", u)
	}
	if !strings.Contains(u, "client_id=test-client") {
		t.Errorf("missing client_id in %q", u)
	}
	if !strings.Contains(u, "redirect_uri=") {
		t.Errorf("missing redirect_uri in %q", u)
	}
	if !strings.Contains(u, "code_challenge_method=S256") {
		t.Errorf("missing code_challenge_method in %q", u)
	}
	if !strings.Contains(u, "code_challenge=") {
		t.Errorf("missing code_challenge in %q", u)
	}
	if !strings.Contains(u, "state=mystate") {
		t.Errorf("missing state in %q", u)
	}
	if !strings.Contains(u, "scope=openid+email+profile") {
		t.Errorf("missing scope in %q", u)
	}
}

func TestS256Challenge(t *testing.T) {
	// The challenge must be deterministic for a given verifier.
	v := "test-verifier"
	c1 := s256Challenge(v)
	c2 := s256Challenge(v)
	if c1 != c2 {
		t.Errorf("challenge not deterministic: %q != %q", c1, c2)
	}
	// Different verifiers produce different challenges.
	c3 := s256Challenge("other-verifier")
	if c1 == c3 {
		t.Error("different verifiers should produce different challenges")
	}
}

func TestLoginURL(t *testing.T) {
	srv, issuer, _ := fakeProvider(t)
	c := newTestClient(t, srv, issuer)

	if got := c.LoginURL(""); !strings.Contains(got, "/login") {
		t.Errorf("LoginURL() = %q, expected /login", got)
	}
	if got := c.LoginURL("/dashboard"); !strings.Contains(got, "redirect_uri") {
		t.Errorf("LoginURL(/dashboard) = %q, expected redirect_uri param", got)
	}
	if got := c.LogoutURL(); !strings.Contains(got, "/logout") {
		t.Errorf("LogoutURL() = %q", got)
	}
}
