# oidclient

> **Experimental — internal use.** This library is developed for
> [infodancer](https://github.com/infodancer) projects that authenticate
> against [infodancer/webauth](https://github.com/infodancer/webauth). The API
> is unstable and may change without notice. If you're looking for a
> general-purpose OIDC relying party library for Go, consider
> [coreos/go-oidc](https://github.com/coreos/go-oidc).

OIDC relying party client for Go web applications. Wraps
[coreos/go-oidc](https://github.com/coreos/go-oidc) for discovery, JWKS, and
token verification, and [golang.org/x/oauth2](https://pkg.go.dev/golang.org/x/oauth2)
for the authorization code flow with PKCE. Adds cookie helpers and a
convenience API on top.

## Features

- **OIDC autodiscovery** via go-oidc `Provider`
- **JWKS caching and key rotation** handled by go-oidc
- **RS256 JWT validation** with issuer and expiry enforcement
- **PKCE (S256)** via x/oauth2
- **Authorization code flow** — authorize URL, token exchange, ID token verification
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
    ClientID:    "myapp",
    CallbackURL: "https://myapp.example.com/auth/callback",
})
```

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

MIT — see [LICENSE](LICENSE).
