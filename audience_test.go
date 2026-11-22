package oidclient

import (
	"context"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	jwtgo "github.com/golang-jwt/jwt/v5"
)

// audProvider is fakeProvider plus a signer that controls the aud claim, which
// the shared issueToken helper fixes to the test client.
func audProvider(t *testing.T) (issuer string, mint func(aud any) string, cfg Config) {
	t.Helper()
	srv, issuer, _, priv := fakeProviderWithKey(t)
	mint = func(aud any) string {
		now := time.Now()
		claims := jwtgo.MapClaims{
			"iss": issuer, "sub": "user-1", "email": "a@example.com",
			"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		}
		if aud != nil {
			claims["aud"] = aud
		}
		return signTestToken(t, priv, claims)
	}
	return issuer, mint, Config{
		IssuerURL: issuer, CookieName: "test_jwt",
		ClientID: "test-client", CallbackURL: srv.URL + "/auth/callback",
	}
}

func signTestToken(t *testing.T, priv *rsa.PrivateKey, claims jwtgo.MapClaims) string {
	t.Helper()
	tok := jwtgo.NewWithClaims(jwtgo.SigningMethodRS256, claims)
	tok.Header["kid"] = "test-kid"
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

// An access token is accepted only when it was issued to this client. A token
// the same issuer signed for a different client is valid in every other
// respect, which is exactly why the audience has to be checked.
func TestValidate_Audience(t *testing.T) {
	_, mint, cfg := audProvider(t)
	c, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, tc := range []struct {
		name string
		aud  any
		ok   bool
	}{
		{"this client", "test-client", true},
		{"this client among several", []string{"other", "test-client"}, true},
		{"another client", "other-client", false},
		{"several, none this client", []string{"a", "b"}, false},
		{"no audience", nil, false},
		{"prefix of this client", "test-clien", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims, err := c.Validate(context.Background(), mint(tc.aud))
			if tc.ok {
				if err != nil || claims.Sub != "user-1" {
					t.Fatalf("Validate = %v, %v; want accepted", claims, err)
				}
				return
			}
			if !errors.Is(err, ErrWrongAudience) {
				t.Fatalf("Validate = %v, %v; want ErrWrongAudience", claims, err)
			}
		})
	}
}

// AllowMissingAudience is for an issuer, or a grant, that emits no aud. It
// excuses absence only: a token that names another client is still refused.
func TestValidate_AllowMissingAudience(t *testing.T) {
	_, mint, cfg := audProvider(t)
	cfg.AllowMissingAudience = true
	c, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.Validate(context.Background(), mint(nil)); err != nil {
		t.Errorf("no audience with the opt-out: %v, want accepted", err)
	}
	if _, err := c.Validate(context.Background(), mint("test-client")); err != nil {
		t.Errorf("own audience with the opt-out: %v, want accepted", err)
	}
	if _, err := c.Validate(context.Background(), mint("other-client")); !errors.Is(err, ErrWrongAudience) {
		t.Errorf("another client's token with the opt-out: %v, want ErrWrongAudience", err)
	}
}

// A Client with no client id only validates tokens; it has no identity for a
// token to be bound to, so there is nothing to compare.
func TestValidate_NoClientIDHasNoAudienceToRequire(t *testing.T) {
	issuer, mint, _ := audProvider(t)
	c, err := New(context.Background(), Config{IssuerURL: issuer, CookieName: "test_jwt"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.Validate(context.Background(), mint(nil)); err != nil {
		t.Errorf("validate-only client: %v, want accepted", err)
	}
}
