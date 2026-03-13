package oidclient

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
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

// jwksHandler returns an http.Handler that serves a JWKS document for the given key.
func jwksHandler(pub *rsa.PublicKey, kid string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA",
				"kid": kid,
				"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			}},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	})
}

// issueTestToken creates a signed JWT with the given claims for testing.
func issueTestToken(t *testing.T, priv *rsa.PrivateKey, kid, issuer, sub, email string, ttl time.Duration) string {
	t.Helper()
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":   issuer,
		"sub":   sub,
		"email": email,
		"name":  "Test User",
		"roles": []string{"user"},
		"iat":   now.Unix(),
		"exp":   now.Add(ttl).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

func TestValidate_Success(t *testing.T) {
	priv, pub := testKeyPair(t)
	kid := "test-kid-1"

	jwks := httptest.NewServer(jwksHandler(pub, kid))
	defer jwks.Close()

	c, err := New(Config{
		Issuer:       "https://auth.example.com",
		CookieName:   "test_jwt",
		JWKSEndpoint: jwks.URL,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	token := issueTestToken(t, priv, kid, "https://auth.example.com", "user-123", "alice@example.com", time.Hour)

	claims, err := c.Validate(token)
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
	priv, pub := testKeyPair(t)
	kid := "test-kid-2"

	jwks := httptest.NewServer(jwksHandler(pub, kid))
	defer jwks.Close()

	c, err := New(Config{
		JWKSEndpoint: jwks.URL,
		CookieName:   "jwt",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	token := issueTestToken(t, priv, kid, "https://auth.example.com", "user-1", "a@b.com", -time.Hour)

	_, err = c.Validate(token)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestValidate_IssuerMismatch(t *testing.T) {
	priv, pub := testKeyPair(t)
	kid := "test-kid-3"

	jwks := httptest.NewServer(jwksHandler(pub, kid))
	defer jwks.Close()

	c, err := New(Config{
		Issuer:       "https://correct.example.com",
		JWKSEndpoint: jwks.URL,
		CookieName:   "jwt",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	token := issueTestToken(t, priv, kid, "https://wrong.example.com", "user-1", "a@b.com", time.Hour)

	_, err = c.Validate(token)
	if err == nil {
		t.Fatal("expected error for issuer mismatch")
	}
}

func TestValidateCookie(t *testing.T) {
	priv, pub := testKeyPair(t)
	kid := "test-kid-4"

	jwks := httptest.NewServer(jwksHandler(pub, kid))
	defer jwks.Close()

	c, err := New(Config{
		JWKSEndpoint: jwks.URL,
		CookieName:   "sf_jwt",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	token := issueTestToken(t, priv, kid, "", "user-42", "bob@example.com", time.Hour)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "sf_jwt", Value: token})

	claims, err := c.ValidateCookie(req)
	if err != nil {
		t.Fatalf("ValidateCookie: %v", err)
	}
	if claims.Sub != "user-42" {
		t.Errorf("sub = %q, want user-42", claims.Sub)
	}
}

func TestValidateCookie_Missing(t *testing.T) {
	priv, pub := testKeyPair(t)
	_ = priv
	kid := "test-kid-5"

	jwks := httptest.NewServer(jwksHandler(pub, kid))
	defer jwks.Close()

	c, err := New(Config{
		JWKSEndpoint: jwks.URL,
		CookieName:   "sf_jwt",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err = c.ValidateCookie(req)
	if err == nil {
		t.Fatal("expected error for missing cookie")
	}
}

func TestDiscovery(t *testing.T) {
	priv, pub := testKeyPair(t)
	_ = priv
	kid := "disc-kid"

	mux := http.NewServeMux()
	mux.Handle("/t/test/.well-known/jwks.json", jwksHandler(pub, kid))
	mux.HandleFunc("/t/test/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		doc := map[string]string{
			"jwks_uri":               "JWKS_PLACEHOLDER",
			"authorization_endpoint": "AUTH_PLACEHOLDER",
			"token_endpoint":         "TOKEN_PLACEHOLDER",
		}
		// These will be filled with the real server URL in the test.
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Re-register with correct URLs now that we know the server address.
	mux2 := http.NewServeMux()
	mux2.Handle("/t/test/.well-known/jwks.json", jwksHandler(pub, kid))
	mux2.HandleFunc("/t/test/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		doc := map[string]string{
			"jwks_uri":               srv.URL + "/t/test/.well-known/jwks.json",
			"authorization_endpoint": srv.URL + "/t/test/authorize",
			"token_endpoint":         srv.URL + "/t/test/token",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	})
	// Swap handler.
	srv.Config.Handler = mux2

	c, err := New(Config{
		IssuerURL:   srv.URL + "/t/test",
		CookieName:  "jwt",
		ClientID:    "myapp",
		CallbackURL: "https://app.example.com/auth/callback",
	})
	if err != nil {
		t.Fatalf("New with discovery: %v", err)
	}

	if !c.FlowConfigured() {
		t.Error("expected FlowConfigured() = true after discovery")
	}

	// The authorize URL should use the discovered endpoint.
	authURL := c.AuthorizeURL("state123", "challenge456")
	if authURL == "" {
		t.Fatal("AuthorizeURL returned empty string")
	}
	if got := c.discoveredAuthorizeURL; got != srv.URL+"/t/test/authorize" {
		t.Errorf("discoveredAuthorizeURL = %q", got)
	}
}

func TestAuthorizeURL_Manual(t *testing.T) {
	// Without discovery, using TenantID + WebauthURL.
	priv, pub := testKeyPair(t)
	_ = priv
	kid := "man-kid"

	jwks := httptest.NewServer(jwksHandler(pub, kid))
	defer jwks.Close()

	c, err := New(Config{
		WebauthURL:   "https://auth.example.com",
		TenantID:     "myco",
		JWKSEndpoint: jwks.URL,
		CookieName:   "jwt",
		ClientID:     "sf",
		CallbackURL:  "https://sf.example.com/auth/callback",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if !c.FlowConfigured() {
		t.Error("expected FlowConfigured() = true")
	}

	u := c.AuthorizeURL("s", "c")
	if u == "" {
		t.Fatal("empty authorize URL")
	}
	// Should contain the manual base.
	if got := "https://auth.example.com/t/myco/authorize"; !contains(u, got) {
		t.Errorf("AuthorizeURL = %q, expected to contain %q", u, got)
	}
}

func TestPKCE(t *testing.T) {
	v, err := GenerateVerifier()
	if err != nil {
		t.Fatalf("GenerateVerifier: %v", err)
	}
	if len(v) == 0 {
		t.Fatal("empty verifier")
	}

	c := Challenge(v)
	if len(c) == 0 {
		t.Fatal("empty challenge")
	}

	// Challenge should be deterministic.
	if c2 := Challenge(v); c2 != c {
		t.Errorf("Challenge not deterministic: %q != %q", c, c2)
	}

	// Different verifiers → different challenges.
	v2, _ := GenerateVerifier()
	if Challenge(v2) == c {
		t.Error("different verifiers produced same challenge")
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

	// Test reading flow cookie values.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: CookieVerifier, Value: "v"})
	req.AddCookie(&http.Cookie{Name: CookieState, Value: "s"})

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

	// Clear it.
	rr2 := httptest.NewRecorder()
	ClearSessionCookie(rr2, "sf_jwt", true)
	cleared := rr2.Result().Cookies()
	if len(cleared) != 1 || cleared[0].MaxAge >= 0 {
		t.Error("expected cleared cookie with negative MaxAge")
	}
}

func TestLoginURL(t *testing.T) {
	priv, pub := testKeyPair(t)
	_ = priv
	kid := "url-kid"

	jwks := httptest.NewServer(jwksHandler(pub, kid))
	defer jwks.Close()

	c, err := New(Config{
		WebauthURL:   "https://auth.example.com",
		JWKSEndpoint: jwks.URL,
		CookieName:   "jwt",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if got := c.LoginURL(""); got != "https://auth.example.com/login" {
		t.Errorf("LoginURL() = %q", got)
	}
	if got := c.LoginURL("/dashboard"); !contains(got, "redirect_uri") {
		t.Errorf("LoginURL(/dashboard) = %q, expected redirect_uri param", got)
	}
	if got := c.LogoutURL(); got != "https://auth.example.com/logout" {
		t.Errorf("LogoutURL() = %q", got)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsStr(s, sub))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
