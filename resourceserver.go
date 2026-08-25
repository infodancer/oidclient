package oidclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// Resource-server mode.
//
// A relying party obtains tokens; a resource server validates ones it did not
// obtain. Both are consumers of the same provider, which is why they live in
// the same package, but the two roles differ in ways that make [Client] the
// wrong type for the second job:
//
//   - A resource server MUST check the audience. [Client] deliberately skips it
//     (SkipClientIDCheck), because a website validating its own session cookie
//     has no audience to compare against. For a resource server, that check is
//     the control that stops one application replaying its users' tokens
//     against a peer on the same issuer.
//   - A resource server runs no flows, so it must never register itself as a
//     client. [Client]'s constructor auto-registers via RFC 7591 whenever the
//     provider advertises a registration endpoint.
//   - A resource server acts on the scope claim, which [Claims] does not carry.
//
// Signature verification, key-set caching, and rotation come from
// [github.com/coreos/go-oidc/v3], as they do on the relying-party path. Two
// properties are layered on top of it here, both enforced by keyFetchGuard:
// a floor between key-set refetches, and telling an unreachable authorization
// server apart from a bad token.

// Sentinel errors returned by [ResourceServer.Verify].
var (
	// ErrInvalidToken means the token does not authenticate: bad signature,
	// wrong issuer, wrong or missing audience, expired, malformed. Callers
	// answer 401.
	ErrInvalidToken = errors.New("oidclient: invalid token")

	// ErrKeysUnavailable means the token could not be checked because the
	// authorization server's key set could not be loaded. Callers answer 500,
	// never 401: telling a client its token is bad when the truth is that the
	// issuer is down sends it into a reauthentication loop against a server
	// that is already struggling.
	ErrKeysUnavailable = errors.New("oidclient: key set unavailable")
)

// defaultMinKeyRefresh bounds how often an unrecognised key id may force an
// outbound key-set fetch. Rotation is rare, and the key id is chosen by an
// unauthenticated caller, so this trades a few minutes of staleness after a
// rotation for not handing anyone an amplifier aimed at the provider.
const defaultMinKeyRefresh = 5 * time.Minute

// ResourceServerConfig configures a [ResourceServer].
type ResourceServerConfig struct {
	// IssuerURL is the provider's issuer identifier, compared exactly against
	// the iss claim. Required.
	IssuerURL string

	// Resource is this resource server's own identifier -- for an MCP server,
	// its endpoint URL. A token must name it in aud. Required.
	Resource string

	// JWKSURL is where the provider publishes its signing keys. Optional: when
	// empty it is discovered from IssuerURL, which makes construction depend on
	// the provider being reachable. Setting it explicitly means construction
	// touches the network not at all, so a daemon starts even when its
	// authorization server is down and only token verification is affected.
	JWKSURL string

	// HTTPClient fetches discovery and key-set documents. Defaults to a client
	// with a short timeout: a key fetch happens on the request path.
	HTTPClient *http.Client

	// MinKeyRefresh is the floor between key-set refetches triggered by an
	// unrecognised key id. Defaults to defaultMinKeyRefresh.
	MinKeyRefresh time.Duration
}

// AccessToken is what a verified access token asserts, reduced to the parts a
// resource server acts on.
type AccessToken struct {
	// Subject is the provider's stable identifier for the user (the sub
	// claim). It is the key to provision and look up local users by -- never
	// the email address, which can change and at some providers can be
	// released and re-registered by a different person.
	Subject string

	// Email and Name are display attributes. Never lookup keys.
	Email string
	Name  string

	// EmailVerified is the provider's assertion that the subject controls
	// Email. Carried so a provisioning policy can record it; it is never a
	// reason to match an account by email.
	EmailVerified bool

	// Scopes is the scope claim, already split on whitespace. What a scope
	// permits is the caller's decision; this reports only what was granted.
	Scopes []string

	// Roles is webauth's roles claim, carried through for callers that use it.
	Roles []string

	// Expiry is the validated expiration.
	Expiry time.Time
}

// ResourceServer validates access tokens issued by one provider for one
// resource. It is safe for concurrent use.
type ResourceServer struct {
	cfg      ResourceServerConfig
	verifier *oidc.IDTokenVerifier
	guard    *keyFetchGuard
}

// NewResourceServer returns a ResourceServer for cfg.
//
// When cfg.JWKSURL is set, no network request is made here. When it is empty,
// OIDC discovery runs against cfg.IssuerURL and an unreachable provider is a
// construction error.
func NewResourceServer(ctx context.Context, cfg ResourceServerConfig) (*ResourceServer, error) {
	switch {
	case cfg.IssuerURL == "":
		return nil, errors.New("oidclient: IssuerURL is required")
	case cfg.Resource == "":
		return nil, errors.New("oidclient: Resource is required")
	}
	if cfg.MinKeyRefresh == 0 {
		cfg.MinKeyRefresh = defaultMinKeyRefresh
	}

	base := cfg.HTTPClient
	if base == nil {
		base = &http.Client{Timeout: 10 * time.Second}
	}
	guard := newKeyFetchGuard(base, cfg.MinKeyRefresh)

	// go-oidc resolves the HTTP client from the context it was constructed
	// with, not the one passed per call, so the guarded client is installed
	// here and applies to every later key fetch.
	keyCtx := oidc.ClientContext(ctx, guard.client())

	// The algorithm is policy, not something a token gets to choose: naming
	// RS256 as the only supported algorithm is what defeats algorithm
	// confusion. Audience is checked in Verify rather than here, because the
	// comparison is not string equality (see matchesResource).
	oidcCfg := &oidc.Config{
		SkipClientIDCheck:    true,
		SupportedSigningAlgs: []string{oidc.RS256},
	}

	var verifier *oidc.IDTokenVerifier
	if cfg.JWKSURL != "" {
		verifier = oidc.NewVerifier(cfg.IssuerURL, oidc.NewRemoteKeySet(keyCtx, cfg.JWKSURL), oidcCfg)
	} else {
		provider, err := oidc.NewProvider(keyCtx, cfg.IssuerURL)
		if err != nil {
			return nil, fmt.Errorf("oidclient: discovering %s: %w", cfg.IssuerURL, err)
		}
		// provider.Verifier is used only for its key set; it performs no
		// registration, which is the property that makes this constructor
		// usable for a resource server where New is not.
		verifier = provider.Verifier(oidcCfg)
	}

	return &ResourceServer{cfg: cfg, verifier: verifier, guard: guard}, nil
}

// rsClaims is the wire shape for the claims this package surfaces beyond the
// registered ones go-oidc already parses.
type rsClaims struct {
	Email         string   `json:"email,omitempty"`
	EmailVerified bool     `json:"email_verified,omitempty"`
	Name          string   `json:"name,omitempty"`
	Scope         string   `json:"scope,omitempty"`
	Roles         []string `json:"roles,omitempty"`
}

// Verify checks token and returns what it asserts.
//
// An error matching [ErrInvalidToken] means the token does not authenticate.
// An error matching [ErrKeysUnavailable] means the check could not be
// performed. Callers must map those to 401 and 500 respectively.
func (rs *ResourceServer) Verify(ctx context.Context, token string) (*AccessToken, error) {
	// Snapshot the guard before verifying so a key fetch that fails during
	// this call can be told apart from a token that is simply bad. go-oidc
	// flattens some of those failures into an unwrappable string, so the fetch
	// is observed directly rather than recovered from its error.
	mark := rs.guard.mark()

	idToken, err := rs.verifier.Verify(ctx, token)
	if err != nil {
		if fetchErr, failed := rs.guard.failedSince(mark); failed {
			return nil, fmt.Errorf("%w: %w", ErrKeysUnavailable, fetchErr)
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	if !matchesResource(idToken.Audience, rs.cfg.Resource) {
		return nil, fmt.Errorf("%w: audience %v does not name %s",
			ErrInvalidToken, idToken.Audience, rs.cfg.Resource)
	}
	if idToken.Subject == "" {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, ErrMissingSub)
	}

	var c rsClaims
	if err := idToken.Claims(&c); err != nil {
		return nil, fmt.Errorf("%w: extracting claims: %v", ErrInvalidToken, err)
	}

	return &AccessToken{
		Subject:       idToken.Subject,
		Email:         c.Email,
		EmailVerified: c.EmailVerified,
		Name:          c.Name,
		Scopes:        strings.Fields(c.Scope),
		Roles:         c.Roles,
		Expiry:        idToken.Expiry,
	}, nil
}

// matchesResource reports whether any audience value names resource, treating a
// URI with an empty path as equivalent to one with a path of "/" and comparing
// everything else exactly.
//
// RFC 9728 §3.3 requires simple string comparison, but RFC 9728 canonicalises
// the resource identifier with a trailing slash while RFC 8707 resource
// indicators routinely omit it, and providers differ in which form they echo
// into aud. Strict byte equality therefore fails on legitimate configurations.
// Scheme, host, and path stay strict so token confusion across genuinely
// distinct resources still fails closed.
func matchesResource(audience []string, resource string) bool {
	want := strings.TrimSuffix(resource, "/")
	for _, a := range audience {
		if a == resource || strings.TrimSuffix(a, "/") == want {
			return true
		}
	}
	return false
}

// keyFetchGuard fronts the provider's key-set fetches. It exists because
// go-oidc offers no hook between "this key id is unknown" and the HTTP request
// that follows, and the HTTP client is the one seam that sits between them.
//
// It does two things: refuses fetches that arrive inside the refresh window,
// and records failures so a caller can tell an unreachable provider from a bad
// token.
type keyFetchGuard struct {
	base        http.RoundTripper
	minInterval time.Duration

	mu          sync.Mutex
	loaded      bool      // a fetch has succeeded at least once
	lastRefresh time.Time // last refetch after the initial load, not the load itself
	failures    uint64    // monotonic count of failed fetches
	lastErr     error
}

// errThrottled is returned to go-oidc in place of performing a fetch that
// arrived inside the refresh window. It is deliberately not an
// ErrKeysUnavailable: nothing is wrong with the provider, we simply declined to
// ask it again this soon, and the outcome for the caller is an unknown key id.
var errThrottled = errors.New("oidclient: key-set refresh throttled")

func newKeyFetchGuard(client *http.Client, minInterval time.Duration) *keyFetchGuard {
	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	return &keyFetchGuard{base: base, minInterval: minInterval}
}

// client returns an *http.Client whose transport is the guard.
func (g *keyFetchGuard) client() *http.Client {
	return &http.Client{Transport: g, Timeout: 10 * time.Second}
}

func (g *keyFetchGuard) RoundTrip(req *http.Request) (*http.Response, error) {
	g.mu.Lock()
	// Two fetches are never throttled: the initial load, because until it
	// succeeds there is nothing to verify against and it is not caller-
	// triggered in the way a refetch is; and the first refetch after it, so a
	// key rotation is picked up immediately rather than after the window.
	// Everything after that is a caller choosing a key id we do not have.
	if g.loaded {
		if !g.lastRefresh.IsZero() && time.Since(g.lastRefresh) < g.minInterval {
			g.mu.Unlock()
			return nil, errThrottled
		}
		g.lastRefresh = time.Now()
	}
	g.mu.Unlock()

	resp, err := g.base.RoundTrip(req)

	g.mu.Lock()
	defer g.mu.Unlock()
	switch {
	case err != nil:
		g.failures++
		g.lastErr = err
	case resp.StatusCode >= 400:
		// go-oidc reports a non-2xx key-set response without wrapping, so this
		// is the only place the distinction survives.
		g.failures++
		g.lastErr = fmt.Errorf("key set request returned %s", resp.Status)
	default:
		g.loaded = true
	}
	return resp, err
}

// mark snapshots the failure counter.
func (g *keyFetchGuard) mark() uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.failures
}

// failedSince reports whether a key fetch failed since mark, and why.
//
// Concurrent verifications share one counter, so a failure raised by another
// in-flight call can be attributed here. That is acceptable: a failing key set
// is failing for every caller at once, and the classification they all want is
// the same one.
func (g *keyFetchGuard) failedSince(mark uint64) (error, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.failures > mark {
		return g.lastErr, true
	}
	return nil, false
}
