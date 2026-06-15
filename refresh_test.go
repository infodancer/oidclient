package oidclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	jwtgo "github.com/golang-jwt/jwt/v5"
)

// refreshProvider is a fake IdP whose token endpoint issues refresh tokens and
// rotates them on the refresh grant, mirroring webauth's behaviour. lastGrant
// records the most recent grant_type seen so tests can assert the wire call.
type refreshProvider struct {
	srv       *httptest.Server
	issuer    string
	lastGrant string
}

// newRefreshProvider starts a provider that signs access/ID tokens and rotates
// refresh tokens. The authorization_code grant returns refresh token "rt-1";
// the refresh_token grant returns the presented token with "-rN" appended,
// where N is the running refresh count, so the rotation is observable.
func newRefreshProvider(t *testing.T, audience string) *refreshProvider {
	t.Helper()
	priv, pub := testKeyPair(t)
	kid := "test-kid"
	rp := &refreshProvider{}
	var baseURL string
	refreshes := 0

	sign := func(claims jwtgo.MapClaims) string {
		tok := jwtgo.NewWithClaims(jwtgo.SigningMethodRS256, claims)
		tok.Header["kid"] = kid
		s, err := tok.SignedString(priv)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		return s
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                baseURL,
			"authorization_endpoint":                baseURL + "/authorize",
			"token_endpoint":                        baseURL + "/token",
			"jwks_uri":                              baseURL + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		rp.lastGrant = r.PostForm.Get("grant_type")

		now := time.Now()
		base := jwtgo.MapClaims{
			"iss": baseURL, "sub": "user-9", "email": "u@example.com",
			"name": "Refresh User", "roles": []string{"user"},
			"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		}
		access := sign(base)
		idClaims := jwtgo.MapClaims{"aud": audience}
		for k, v := range base {
			idClaims[k] = v
		}
		id := sign(idClaims)

		refreshTok := "rt-1"
		if rp.lastGrant == "refresh_token" {
			refreshes++
			refreshTok = r.PostForm.Get("refresh_token") + "-r" + strconv.Itoa(refreshes)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  access,
			"id_token":      id,
			"refresh_token": refreshTok,
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	})

	rp.srv = httptest.NewServer(mux)
	baseURL = rp.srv.URL
	rp.issuer = rp.srv.URL
	t.Cleanup(rp.srv.Close)
	return rp
}

func newRefreshClient(t *testing.T, rp *refreshProvider) *Client {
	t.Helper()
	c, err := New(context.Background(), Config{
		IssuerURL:     rp.issuer,
		CookieName:    "test_jwt",
		ClientID:      "test-client",
		CallbackURL:   rp.srv.URL + "/auth/callback",
		OfflineAccess: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestOfflineAccessScope(t *testing.T) {
	srv, issuer, _ := fakeProvider(t)

	off, err := New(context.Background(), Config{
		IssuerURL: issuer, CookieName: "j", ClientID: "test-client",
		CallbackURL: srv.URL + "/cb", OfflineAccess: true,
	})
	if err != nil {
		t.Fatalf("New offline: %v", err)
	}
	if u := off.AuthorizeURL("s", "v"); !strings.Contains(u, "offline_access") {
		t.Errorf("OfflineAccess client AuthorizeURL %q should request offline_access", u)
	}

	on := newTestClient(t, srv, issuer) // OfflineAccess defaults to false
	if u := on.AuthorizeURL("s", "v"); strings.Contains(u, "offline_access") {
		t.Errorf("default client AuthorizeURL %q must not request offline_access", u)
	}
}

func TestExchange_ReturnsRefreshTokenAndExpiry(t *testing.T) {
	rp := newRefreshProvider(t, "test-client")
	c := newRefreshClient(t, rp)

	toks, claims, err := c.Exchange(context.Background(), "code", "verifier")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if toks.AccessToken == "" {
		t.Error("expected access token")
	}
	if toks.RefreshToken != "rt-1" {
		t.Errorf("refresh token = %q, want rt-1", toks.RefreshToken)
	}
	if toks.Expiry.IsZero() || toks.Expiry.Before(time.Now()) {
		t.Errorf("expiry = %v, want a future time", toks.Expiry)
	}
	if claims.Sub != "user-9" {
		t.Errorf("sub = %q, want user-9", claims.Sub)
	}
	if claims.Exp == 0 {
		t.Error("claims.Exp should be populated from the token")
	}
}

func TestExchangeCode_BackwardCompatible(t *testing.T) {
	rp := newRefreshProvider(t, "test-client")
	c := newRefreshClient(t, rp)

	access, claims, err := c.ExchangeCode(context.Background(), "code", "verifier")
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if access == "" || claims == nil {
		t.Fatal("ExchangeCode should still return access token and claims")
	}
}

func TestRefresh_RotatesToken(t *testing.T) {
	rp := newRefreshProvider(t, "test-client")
	c := newRefreshClient(t, rp)

	toks, claims, err := c.Refresh(context.Background(), "rt-old")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if rp.lastGrant != "refresh_token" {
		t.Errorf("grant_type = %q, want refresh_token", rp.lastGrant)
	}
	// The IdP rotated the token; the caller must receive the new one, not the
	// token it sent in.
	if toks.RefreshToken != "rt-old-r1" {
		t.Errorf("rotated refresh token = %q, want rt-old-r1", toks.RefreshToken)
	}
	if toks.AccessToken == "" {
		t.Error("expected a renewed access token")
	}
	if claims.Sub != "user-9" {
		t.Errorf("sub = %q, want user-9", claims.Sub)
	}

	// The renewed access token validates, and a second refresh chains off the
	// rotated token.
	if _, err := c.Validate(context.Background(), toks.AccessToken); err != nil {
		t.Errorf("renewed access token failed validation: %v", err)
	}
	toks2, _, err := c.Refresh(context.Background(), toks.RefreshToken)
	if err != nil {
		t.Fatalf("second Refresh: %v", err)
	}
	if toks2.RefreshToken != "rt-old-r1-r2" {
		t.Errorf("second rotation = %q, want rt-old-r1-r2", toks2.RefreshToken)
	}
}

func TestRefresh_EmptyToken(t *testing.T) {
	rp := newRefreshProvider(t, "test-client")
	c := newRefreshClient(t, rp)

	if _, _, err := c.Refresh(context.Background(), ""); !errors.Is(err, ErrNoRefreshToken) {
		t.Errorf("Refresh(\"\") error = %v, want ErrNoRefreshToken", err)
	}
}

func TestRefresh_NotReady(t *testing.T) {
	// A lazy client whose discovery never completes must report ErrNotReady
	// rather than attempting a refresh against an unknown endpoint.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, err := NewLazy(ctx, Config{
		IssuerURL: "http://127.0.0.1:1/unreachable", CookieName: "j",
		ClientID: "test-client", OfflineAccess: true,
	})
	if err != nil {
		t.Fatalf("NewLazy: %v", err)
	}
	if _, _, err := c.Refresh(context.Background(), "rt"); !errors.Is(err, ErrNotReady) {
		t.Errorf("Refresh on not-ready client = %v, want ErrNotReady", err)
	}
}

func TestClaims_ExpiresAt(t *testing.T) {
	srv, issuer, issue := fakeProvider(t)
	c := newTestClient(t, srv, issuer)

	token := issue("user-1", "a@b.com", time.Hour)
	claims, err := c.Validate(context.Background(), token)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.Exp == 0 {
		t.Fatal("Validate should populate Claims.Exp")
	}
	got := claims.ExpiresAt()
	if d := time.Until(got); d < 55*time.Minute || d > time.Hour+time.Minute {
		t.Errorf("ExpiresAt() = %v (%v from now), want ~1h out", got, d)
	}
}
