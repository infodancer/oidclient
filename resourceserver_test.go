package oidclient

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	jwtgo "github.com/golang-jwt/jwt/v5"
)

const testResource = "https://memstore.example.test/memstore/mcp"

// rsProvider is a fake authorization server for resource-server tests. Unlike
// fakeProviderMux it exposes the signing key and key id, so a test can mint a
// token with any claim set, sign it with the wrong key, or name a key id the
// server does not publish. It also counts JWKS fetches, which is how the
// refresh throttle is observed.
type rsProvider struct {
	*httptest.Server
	priv    *rsa.PrivateKey
	kid     string
	keys    map[string]*rsa.PublicKey
	fetches atomic.Int64
}

func newRSProvider(t *testing.T) *rsProvider {
	t.Helper()
	priv, pub := testKeyPair(t)
	p := &rsProvider{priv: priv, kid: "rs-kid-1"}
	p.keys = map[string]*rsa.PublicKey{p.kid: pub}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		doc := map[string]any{
			"issuer":                                p.URL,
			"authorization_endpoint":                p.URL + "/authorize",
			"token_endpoint":                        p.URL + "/token",
			"jwks_uri":                              p.URL + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		p.fetches.Add(1)
		keys := []map[string]any{}
		for kid, pub := range p.keys {
			keys = append(keys, map[string]any{
				"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig",
				"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			})
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	})

	p.Server = httptest.NewServer(mux)
	t.Cleanup(p.Close)
	return p
}

// claims returns a claim set that verifies cleanly, for a test to then break in
// exactly one place.
func (p *rsProvider) claims() jwtgo.MapClaims {
	now := time.Now()
	return jwtgo.MapClaims{
		"iss":   p.URL,
		"sub":   "user-abc123",
		"aud":   testResource,
		"email": "someone@example.test",
		"scope": "read write",
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	}
}

func (p *rsProvider) sign(t *testing.T, c jwtgo.MapClaims) string {
	t.Helper()
	return p.signAs(t, p.priv, p.kid, c)
}

func (p *rsProvider) signAs(t *testing.T, key *rsa.PrivateKey, kid string, c jwtgo.MapClaims) string {
	t.Helper()
	tok := jwtgo.NewWithClaims(jwtgo.SigningMethodRS256, c)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

func newRS(t *testing.T, p *rsProvider) *ResourceServer {
	t.Helper()
	rs, err := NewResourceServer(context.Background(), ResourceServerConfig{
		IssuerURL: p.URL,
		Resource:  testResource,
		JWKSURL:   p.URL + "/jwks",
	})
	if err != nil {
		t.Fatalf("NewResourceServer: %v", err)
	}
	return rs
}

func TestResourceServerVerifyAcceptsValidToken(t *testing.T) {
	p := newRSProvider(t)
	rs := newRS(t, p)

	got, err := rs.Verify(context.Background(), p.sign(t, p.claims()))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Subject != "user-abc123" {
		t.Errorf("Subject = %q, want user-abc123", got.Subject)
	}
	if got.Email != "someone@example.test" {
		t.Errorf("Email = %q, want someone@example.test", got.Email)
	}
	// The scope claim is space-delimited per RFC 6749 and reaches the caller
	// already split, because every consumer wants the list.
	if len(got.Scopes) != 2 || got.Scopes[0] != "read" || got.Scopes[1] != "write" {
		t.Errorf("Scopes = %v, want [read write]", got.Scopes)
	}
	if got.Expiry.IsZero() {
		t.Error("Expiry is zero")
	}
}

// Every case here is a token that must not authenticate. Each is a distinct way
// a token that would otherwise parse cleanly fails to be OUR token.
func TestResourceServerVerifyRejects(t *testing.T) {
	tests := []struct {
		name  string
		token func(t *testing.T, p *rsProvider) string
	}{
		{
			// The confused-deputy case, and the reason audience binding is
			// mandatory for a resource server: a token the same issuer minted
			// for another application must not open this one. Note that the RP
			// path deliberately skips this check (SkipClientIDCheck) because a
			// website validating its own session has no audience to compare.
			name: "audience naming a different resource",
			token: func(t *testing.T, p *rsProvider) string {
				c := p.claims()
				c["aud"] = "https://herald.example.test/mcp"
				return p.sign(t, c)
			},
		},
		{
			// An unaudienced token is every resource's token. webauth emits
			// exactly this shape today.
			name: "no audience at all",
			token: func(t *testing.T, p *rsProvider) string {
				c := p.claims()
				delete(c, "aud")
				return p.sign(t, c)
			},
		},
		{
			name: "expired",
			token: func(t *testing.T, p *rsProvider) string {
				c := p.claims()
				c["exp"] = time.Now().Add(-time.Minute).Unix()
				return p.sign(t, c)
			},
		},
		{
			// A token with no expiry never stops being valid.
			name: "no expiry claim",
			token: func(t *testing.T, p *rsProvider) string {
				c := p.claims()
				delete(c, "exp")
				return p.sign(t, c)
			},
		},
		{
			name: "issued by a different authorization server",
			token: func(t *testing.T, p *rsProvider) string {
				c := p.claims()
				c["iss"] = "https://evil.example.test/t/memstore"
				return p.sign(t, c)
			},
		},
		{
			name: "signed by a key the JWKS does not publish",
			token: func(t *testing.T, p *rsProvider) string {
				other, _ := testKeyPair(t)
				return p.signAs(t, other, p.kid, p.claims())
			},
		},
		{
			name: "kid naming a key the JWKS does not have",
			token: func(t *testing.T, p *rsProvider) string {
				return p.signAs(t, p.priv, "nonexistent-kid", p.claims())
			},
		},
		{
			// Algorithm confusion: HMAC signed with the RSA public key as the
			// shared secret.
			name: "HMAC-signed using the public key as the secret",
			token: func(t *testing.T, p *rsProvider) string {
				pub, err := x509.MarshalPKIXPublicKey(&p.priv.PublicKey)
				if err != nil {
					t.Fatalf("marshal public key: %v", err)
				}
				tok := jwtgo.NewWithClaims(jwtgo.SigningMethodHS256, p.claims())
				tok.Header["kid"] = p.kid
				s, err := tok.SignedString(pub)
				if err != nil {
					t.Fatalf("sign HS256: %v", err)
				}
				return s
			},
		},
		{
			name: "alg none",
			token: func(t *testing.T, p *rsProvider) string {
				tok := jwtgo.NewWithClaims(jwtgo.SigningMethodNone, p.claims())
				tok.Header["kid"] = p.kid
				s, err := tok.SignedString(jwtgo.UnsafeAllowNoneSignatureType)
				if err != nil {
					t.Fatalf("sign none: %v", err)
				}
				return s
			},
		},
		{
			// Without a subject there is nobody to attribute the call to, and a
			// caller that provisions users would key a row on "".
			name: "no subject",
			token: func(t *testing.T, p *rsProvider) string {
				c := p.claims()
				delete(c, "sub")
				return p.sign(t, c)
			},
		},
		{
			name:  "not a JWT at all",
			token: func(t *testing.T, p *rsProvider) string { return "not.a.token" },
		},
		{
			name:  "empty string",
			token: func(t *testing.T, p *rsProvider) string { return "" },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newRSProvider(t)
			rs := newRS(t, p)
			got, err := rs.Verify(context.Background(), tt.token(t, p))
			if err == nil {
				t.Fatalf("Verify accepted the token, got %+v", got)
			}
			// Callers map ErrInvalidToken to 401 and everything else to 500,
			// so the sentinel has to survive the wrapping.
			if !errors.Is(err, ErrInvalidToken) {
				t.Errorf("error %v does not match ErrInvalidToken", err)
			}
		})
	}
}

// The rejection table proves an HS256 or "none" token is refused, but not WHY:
// the key set holds only RSA keys, so those tokens would fail signature
// verification regardless of what algorithms are configured. That is an
// accident of the key type, not a policy, and it would evaporate the day a key
// set carried a symmetric key.
//
// This pins the policy instead. An algorithm we do not accept must be rejected
// before the key set is consulted at all -- observable because consulting it is
// what triggers the first fetch. Widening SupportedSigningAlgs makes this test
// fail; it makes nothing else fail.
func TestResourceServerRejectsBadAlgorithmBeforeConsultingKeys(t *testing.T) {
	tests := []struct {
		name  string
		token func(t *testing.T, p *rsProvider) string
	}{
		{
			name: "HS256",
			token: func(t *testing.T, p *rsProvider) string {
				pub, err := x509.MarshalPKIXPublicKey(&p.priv.PublicKey)
				if err != nil {
					t.Fatalf("marshal public key: %v", err)
				}
				tok := jwtgo.NewWithClaims(jwtgo.SigningMethodHS256, p.claims())
				tok.Header["kid"] = p.kid
				s, err := tok.SignedString(pub)
				if err != nil {
					t.Fatalf("sign HS256: %v", err)
				}
				return s
			},
		},
		{
			name: "none",
			token: func(t *testing.T, p *rsProvider) string {
				tok := jwtgo.NewWithClaims(jwtgo.SigningMethodNone, p.claims())
				tok.Header["kid"] = p.kid
				s, err := tok.SignedString(jwtgo.UnsafeAllowNoneSignatureType)
				if err != nil {
					t.Fatalf("sign none: %v", err)
				}
				return s
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newRSProvider(t)
			// An explicit JWKS URL means construction fetches nothing, so the
			// key set is still unloaded when the token arrives.
			rs := newRS(t, p)
			if _, err := rs.Verify(context.Background(), tt.token(t, p)); err == nil {
				t.Fatal("Verify accepted the token")
			}
			if got := p.fetches.Load(); got != 0 {
				t.Errorf("key set was fetched %d times; the algorithm should have "+
					"been rejected before the key set was consulted", got)
			}
		})
	}
}

// RFC 9728 canonicalises the resource identifier with a trailing slash while
// RFC 8707 resource indicators routinely omit it, and issuers echo back
// whichever form they were given. Both name the same resource.
func TestResourceServerVerifyAcceptsTrailingSlashVariance(t *testing.T) {
	p := newRSProvider(t)
	rs := newRS(t, p)

	c := p.claims()
	c["aud"] = testResource + "/"
	if _, err := rs.Verify(context.Background(), p.sign(t, c)); err != nil {
		t.Fatalf("Verify rejected a trailing-slash audience: %v", err)
	}
}

// A token may carry several audiences; ours being among them is enough.
func TestResourceServerVerifyAcceptsMultipleAudiences(t *testing.T) {
	p := newRSProvider(t)
	rs := newRS(t, p)

	c := p.claims()
	c["aud"] = []string{"https://herald.example.test/mcp", testResource}
	if _, err := rs.Verify(context.Background(), p.sign(t, c)); err != nil {
		t.Fatalf("Verify rejected a token listing our resource: %v", err)
	}
}

// Key rotation must not need a restart.
func TestResourceServerVerifyPicksUpRotatedKeys(t *testing.T) {
	p := newRSProvider(t)
	rs := newRS(t, p)

	if _, err := rs.Verify(context.Background(), p.sign(t, p.claims())); err != nil {
		t.Fatalf("Verify with the original key: %v", err)
	}

	rotated, rotatedPub := testKeyPair(t)
	p.keys["rs-kid-2"] = rotatedPub
	if _, err := rs.Verify(context.Background(), p.signAs(t, rotated, "rs-kid-2", p.claims())); err != nil {
		t.Fatalf("Verify after rotation: %v", err)
	}
}

// The refetch that makes rotation work is an unauthenticated caller's way of
// making us issue an outbound request: the key id comes from the token. Without
// a floor between fetches, a flood of unknown key ids becomes a flood of JWKS
// requests aimed at the authorization server. go-oidc coalesces concurrent
// fetches but does not throttle sequential ones, so this is ours to enforce.
func TestResourceServerThrottlesKeyRefetch(t *testing.T) {
	p := newRSProvider(t)
	rs, err := NewResourceServer(context.Background(), ResourceServerConfig{
		IssuerURL:     p.URL,
		Resource:      testResource,
		JWKSURL:       p.URL + "/jwks",
		MinKeyRefresh: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewResourceServer: %v", err)
	}

	if _, err := rs.Verify(context.Background(), p.sign(t, p.claims())); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	primed := p.fetches.Load()

	for range 20 {
		_, _ = rs.Verify(context.Background(), p.signAs(t, p.priv, "unknown-kid", p.claims()))
	}
	if got := p.fetches.Load() - primed; got > 1 {
		t.Errorf("20 unknown-kid tokens caused %d JWKS fetches, want at most 1", got)
	}
}

// An authorization server we cannot reach is not a bad token. The distinction
// is a 500 against a 401: answering an outage with a 401 sends every client
// into a reauthentication loop against a server that is already struggling.
func TestResourceServerDistinguishesUnreachableKeys(t *testing.T) {
	p := newRSProvider(t)
	rs := newRS(t, p)
	token := p.sign(t, p.claims())
	p.Close()

	_, err := rs.Verify(context.Background(), token)
	if err == nil {
		t.Fatal("Verify succeeded against an unreachable key set")
	}
	if errors.Is(err, ErrInvalidToken) {
		t.Errorf("unreachable key set reported as an invalid token: %v", err)
	}
	if !errors.Is(err, ErrKeysUnavailable) {
		t.Errorf("error %v does not match ErrKeysUnavailable", err)
	}
}

// A JWKS endpoint answering 503 is the same kind of failure as one that will
// not connect, and must not be reported as a bad token either. go-oidc flattens
// this case (no %w), which is why classification is done by observing the
// fetch rather than by unwrapping its error.
func TestResourceServerTreatsBadJWKSStatusAsUnavailable(t *testing.T) {
	p := newRSProvider(t)
	token := p.sign(t, p.claims())

	// Point a second resource server at a key set that cannot be loaded.
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer failing.Close()

	rs2, err := NewResourceServer(context.Background(), ResourceServerConfig{
		IssuerURL: p.URL,
		Resource:  testResource,
		JWKSURL:   failing.URL,
	})
	if err != nil {
		t.Fatalf("NewResourceServer: %v", err)
	}
	_, err = rs2.Verify(context.Background(), token)
	if err == nil {
		t.Fatal("Verify succeeded against a failing key set")
	}
	if !errors.Is(err, ErrKeysUnavailable) {
		t.Errorf("error %v does not match ErrKeysUnavailable", err)
	}
}

// A resource server runs no flows and must never register itself as a client,
// even though webauth advertises a registration endpoint. This is the property
// that makes the RP constructor unusable for this role.
func TestNewResourceServerDoesNotRegisterAClient(t *testing.T) {
	var registered atomic.Int64
	priv, pub := testKeyPair(t)
	kid := "rs-kid-1"

	mux := http.NewServeMux()
	var base string
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		doc := map[string]any{
			"issuer":                   base,
			"authorization_endpoint":   base + "/authorize",
			"token_endpoint":           base + "/token",
			"jwks_uri":                 base + "/jwks",
			"registration_endpoint":    base + "/register-client",
			"response_types_supported": []string{"code"},
			"subject_types_supported":  []string{"public"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	})
	mux.HandleFunc("/register-client", func(w http.ResponseWriter, r *http.Request) {
		registered.Add(1)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{"client_id": "should-not-happen"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		doc := map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}}}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	base = srv.URL

	// Discovery path: no explicit JWKS URL, so the issuer is discovered.
	rs, err := NewResourceServer(context.Background(), ResourceServerConfig{
		IssuerURL: srv.URL,
		Resource:  testResource,
	})
	if err != nil {
		t.Fatalf("NewResourceServer: %v", err)
	}

	now := time.Now()
	tok := jwtgo.NewWithClaims(jwtgo.SigningMethodRS256, jwtgo.MapClaims{
		"iss": srv.URL, "sub": "u1", "aud": testResource,
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := rs.Verify(context.Background(), signed); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got := registered.Load(); got != 0 {
		t.Errorf("resource server registered itself as a client %d times", got)
	}
}

// Discovery is a convenience: an explicit JWKS URL means construction touches
// the network not at all, so a daemon does not fail to start because its
// authorization server is down.
func TestNewResourceServerWithExplicitJWKSMakesNoRequests(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.NotFound(w, r)
	}))
	defer srv.Close()

	if _, err := NewResourceServer(context.Background(), ResourceServerConfig{
		IssuerURL: srv.URL,
		Resource:  testResource,
		JWKSURL:   srv.URL + "/jwks",
	}); err != nil {
		t.Fatalf("NewResourceServer: %v", err)
	}
	if got := hits.Load(); got != 0 {
		t.Errorf("construction made %d requests, want 0", got)
	}
}

func TestNewResourceServerRejectsIncompleteConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  ResourceServerConfig
	}{
		{"no issuer", ResourceServerConfig{Resource: testResource, JWKSURL: "https://x.test/jwks"}},
		{"no resource", ResourceServerConfig{IssuerURL: "https://x.test", JWKSURL: "https://x.test/jwks"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewResourceServer(context.Background(), tt.cfg); err == nil {
				t.Error("NewResourceServer accepted an incomplete config")
			}
		})
	}
}
