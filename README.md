# oidclient

[![CI](https://github.com/infodancer/oidclient/actions/workflows/ci.yml/badge.svg)](https://github.com/infodancer/oidclient/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/infodancer/oidclient.svg)](https://pkg.go.dev/github.com/infodancer/oidclient)
[![Go Report Card](https://goreportcard.com/badge/github.com/infodancer/oidclient)](https://goreportcard.com/report/github.com/infodancer/oidclient)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

> **Experimental — internal use.** This library is developed for
> [infodancer](https://github.com/infodancer) projects that authenticate
> against [infodancer/webauth](https://github.com/infodancer/webauth). The API
> is unstable and may change without notice. If you're looking for a
> general-purpose OIDC relying party library for Go, consider
> [coreos/go-oidc](https://github.com/coreos/go-oidc).

A thin convenience wrapper around
[coreos/go-oidc](https://github.com/coreos/go-oidc) and
[golang.org/x/oauth2](https://pkg.go.dev/golang.org/x/oauth2) that bundles
OIDC discovery, JWKS-based JWT validation, the authorization code flow with
PKCE, and cookie management into a single `Client` type. No custom
cryptography — all signing and verification is delegated to go-oidc and
go-jose.

## Features

- **OIDC autodiscovery** via go-oidc `Provider`
- **JWKS caching and key rotation** handled by go-oidc
- **RS256 JWT validation** with issuer and expiry enforcement
- **PKCE (S256)** via x/oauth2
- **Authorization code flow** — authorize URL, token exchange, ID token verification
- **RFC 7591 dynamic client registration** — automatic at startup when the provider advertises it
- **Static confidential clients** — set `ClientID` + `ClientSecret` for providers that issue a secret and don't support RFC 7591 (e.g. Google)
- **Cookie helpers** — secure defaults for OAuth flow state and JWT session cookies

## Install

```
go get github.com/infodancer/oidclient
```

## Usage

### Creating a client

```go
client, err := oidclient.New(ctx, oidclient.Config{
    IssuerURL:   "https://auth.example.com/t/mytenant",
    CookieName:  "myapp_jwt",
    ClientID:    "myapp",       // pre-registered fallback; ignored if the provider supports RFC 7591
    ClientName:  "My App",      // sent during dynamic registration (optional)
    CallbackURL: "https://myapp.example.com/auth/callback",
})
```

### Dynamic client registration (RFC 7591)

If the provider's discovery document advertises `registration_endpoint`,
`New` performs RFC 7591 dynamic client registration during startup, posts
client metadata (`client_name`, `redirect_uris`), and uses the
server-assigned `client_id` (and `client_secret`, if returned) for all
subsequent operations. The runtime id is available via `client.ClientID()`
for persistence across restarts:

```go
log.Printf("registered as client_id=%s", client.ClientID())
```

When the provider does not advertise `registration_endpoint`, `Config.ClientID`
is used as-is — the manual-provisioning case (the OIDC client was registered
out-of-band at the provider's admin console). For a **confidential** client that
also issues a secret (e.g. a Google "Web application" credential), set
`Config.ClientSecret` alongside `ClientID`; it is sent in the token-exchange
request body together with the PKCE verifier. Leave it empty for public PKCE
clients. If the provider *does* advertise `registration_endpoint`, dynamic
registration runs and the server-assigned secret supersedes `ClientSecret`.

### Starting the login flow

```go
func handleLogin(w http.ResponseWriter, r *http.Request) {
    verifier := oidclient.GenerateVerifier()
    state, _ := oidclient.GenerateNonce()
    secure := oidclient.IsSecure(r)

    oidclient.SetFlowCookie(w, oidclient.CookieVerifier, verifier, secure)
    oidclient.SetFlowCookie(w, oidclient.CookieState, state, secure)
    oidclient.SetFlowCookie(w, oidclient.CookieRedirect, r.URL.RequestURI(), secure)

    http.Redirect(w, r, client.AuthorizeURL(state, verifier), http.StatusFound)
}
```

### Handling the callback

```go
func handleCallback(w http.ResponseWriter, r *http.Request) {
    state := r.URL.Query().Get("state")
    if state != oidclient.FlowCookieValue(r, oidclient.CookieState) {
        http.Error(w, "invalid state", http.StatusBadRequest)
        return
    }

    verifier := oidclient.FlowCookieValue(r, oidclient.CookieVerifier)
    accessToken, claims, err := client.ExchangeCode(r.Context(), r.URL.Query().Get("code"), verifier)
    if err != nil {
        http.Error(w, "auth failed", http.StatusBadGateway)
        return
    }

    // claims.Sub, claims.Email, claims.Name, claims.Roles are available
    // for user provisioning here.

    secure := oidclient.IsSecure(r)
    oidclient.SetSessionCookie(w, client.CookieName(), accessToken, secure)
    oidclient.ClearFlowCookies(w)

    redirectTo := oidclient.FlowCookieValue(r, oidclient.CookieRedirect)
    if redirectTo == "" {
        redirectTo = "/"
    }
    http.Redirect(w, r, redirectTo, http.StatusFound)
}
```

### Validating requests

```go
func requireAuth(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        claims, err := client.ValidateCookie(r)
        if err != nil {
            // redirect to login...
            return
        }
        // claims.Sub, claims.Email, claims.Name, claims.Roles available
        next.ServeHTTP(w, r)
    })
}
```

## License

Apache-2.0 — see [LICENSE](LICENSE). Vulnerability reporting in
[SECURITY.md](SECURITY.md).
