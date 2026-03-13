# oidclient

> **Experimental — internal use.** This library is developed for
> [infodancer](https://github.com/infodancer) projects that authenticate
> against [infodancer/webauth](https://github.com/infodancer/webauth). The API
> is unstable and may change without notice. If you're looking for a
> general-purpose OIDC relying party library for Go, consider
> [coreos/go-oidc](https://github.com/coreos/go-oidc).

OIDC relying party client for Go web applications. Handles the authorization
code flow with PKCE against an OpenID Connect provider.

## Features

- **OIDC autodiscovery** — fetches endpoints from `.well-known/openid-configuration`
- **JWKS caching** — in-memory key cache with 1-hour TTL and automatic refresh on key ID miss
- **RS256 JWT validation** — issuer checking, expiration enforcement, claims extraction
- **PKCE (S256)** — verifier/challenge generation per RFC 7636
- **Authorization code flow** — authorize URL construction and token exchange
- **Cookie helpers** — secure defaults for OAuth flow state and JWT session cookies

## Install

```
go get github.com/infodancer/oidclient
```

## Usage

### With OIDC autodiscovery

```go
client, err := oidclient.New(oidclient.Config{
    IssuerURL:   "https://auth.example.com/t/mytenant",
    CookieName:  "myapp_jwt",
    ClientID:    "myapp",
    CallbackURL: "https://myapp.example.com/auth/callback",
})
```

### Manual configuration

```go
client, err := oidclient.New(oidclient.Config{
    WebauthURL:   "https://auth.example.com",
    TenantID:     "mytenant",
    JWKSEndpoint: "https://auth.example.com/t/mytenant/.well-known/jwks.json",
    Issuer:       "https://auth.example.com/t/mytenant",
    CookieName:   "myapp_jwt",
    ClientID:     "myapp",
    CallbackURL:  "https://myapp.example.com/auth/callback",
})
```

### Starting the login flow

```go
func handleLogin(w http.ResponseWriter, r *http.Request) {
    verifier, _ := oidclient.GenerateVerifier()
    state, _ := oidclient.GenerateNonce()
    challenge := oidclient.Challenge(verifier)
    secure := oidclient.IsSecure(r)

    oidclient.SetFlowCookie(w, oidclient.CookieVerifier, verifier, secure)
    oidclient.SetFlowCookie(w, oidclient.CookieState, state, secure)
    oidclient.SetFlowCookie(w, oidclient.CookieRedirect, r.URL.RequestURI(), secure)

    http.Redirect(w, r, client.AuthorizeURL(state, challenge), http.StatusFound)
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
    token, err := client.ExchangeCode(r.Context(), r.URL.Query().Get("code"), verifier)
    if err != nil {
        http.Error(w, "auth failed", http.StatusBadGateway)
        return
    }

    secure := oidclient.IsSecure(r)
    oidclient.SetSessionCookie(w, client.CookieName(), token, secure)
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

MIT — see [LICENSE](LICENSE).
