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
- **Session renewal** — `offline_access` opt-in, refresh-token grant with rotation handling, and proactive expiry via `Claims.ExpiresAt`
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

`New` contacts the provider synchronously and fails if it is unreachable. A
web application that must boot even while its IdP is down should use
`NewLazy` instead: it returns immediately, runs discovery in the background
with exponential backoff, and degrades gracefully until the provider is
reached -- `Ready()` reports false, token operations (`Validate`, `Exchange`,
`Refresh`) return `ErrNotReady` (treat as anonymous), `AuthorizeURL` returns `""` (check
`Ready()` before starting a login flow), and `CallbackHandler` responds 503.
An IdP outage then costs sign-in, not the whole site. The context passed to
`NewLazy` must outlive the client; set `Config.Logf` to see retry diagnostics.

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
    tokens, claims, err := client.Exchange(r.Context(), r.URL.Query().Get("code"), verifier)
    if err != nil {
        http.Error(w, "auth failed", http.StatusBadGateway)
        return
    }

    // claims.Sub, claims.Email, claims.Name, claims.Roles are available
    // for user provisioning here. When OfflineAccess is set, persist
    // tokens.RefreshToken to a server-side session store to renew later.

    secure := oidclient.IsSecure(r)
    oidclient.SetSessionCookie(w, client.CookieName(), tokens.AccessToken, secure)
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

`Validate` and `ValidateCookie` accept an access token only if its `aud` names
this client's id, so a token the same issuer signed for another client is
refused (`ErrWrongAudience`). For an issuer or grant that emits no `aud`, set
`Config.AllowMissingAudience`; a token naming a different client is still
refused. Upgrade the provider before a client that requires the claim: a
session whose refreshed token fails validation cannot renew.

### Renewing a session

Set `OfflineAccess: true` on the `Config` so the IdP issues a refresh token,
then persist `tokens.RefreshToken` from `Exchange` (a long-lived, high-value
credential — keep it server-side, not in a browser cookie). When the access
token nears expiry, renew without an interactive redirect:

```go
newTokens, claims, err := client.Refresh(ctx, storedRefreshToken)
if err != nil {
    // ErrNoRefreshToken / a refused grant means the session cannot be
    // renewed silently — fall back to a full login.
    return
}
// The IdP may rotate the refresh token: store newTokens.RefreshToken and
// discard the one just used, or the next Refresh fails replay detection.
save(claims.Sub, newTokens.RefreshToken)
oidclient.SetSessionCookie(w, client.CookieName(), newTokens.AccessToken, secure)
```

Renew proactively rather than waiting for a 401: `Claims.ExpiresAt()` exposes
the access-token expiry, so a caller can refresh a minute ahead of time.

### Managed sessions

The `oidclient/session` subpackage wraps the renewal primitives above into a
full server-side session lifecycle so relying parties don't hand-roll it: the
browser holds an opaque session id, the access and rotating refresh tokens live
server-side (encrypted at rest), and the manager validates and renews on each
request -- collapsing concurrent renewals and guarding the refresh-token replay
race. It persists nothing itself; the host supplies a `session.Store` over its
own database and a `session.Keyring` for the at-rest encryption.

```go
mgr, err := session.New(session.Config{
    Store:      myStore,   // implemented over the host DB
    Renewer:    client,    // the *oidclient.Client
    Keyring:    keyring,   // AES-256-GCM keys from the host's secret store
    CookieName: client.CookieName(),
})
// callback:       mgr.Start(w, r, tokens, claims)
// every request:  claims, err := mgr.Authenticate(r)  // renews transparently
// logout:         mgr.Destroy(w, r)
```

Design and rationale: [docs/session-design.md](docs/session-design.md).

#### Login handlers

`session.NewHandlers` supplies the login endpoints that go with a managed
session, so a site does not write the callback by hand:

```go
h, err := session.NewHandlers(session.HandlerConfig{
    Provider: client,   // the *oidclient.Client
    Sessions: mgr,
    OnAuthenticated: func(r *http.Request, c *oidclient.Claims) (session.Login, error) {
        isNew, err := provisionUser(r.Context(), c) // optional; an error aborts the login
        return session.Login{Data: isNew}, err
    },
    // Optional: complete the response yourself (a popup that closes, an extra
    // cookie) instead of the default 302. Login.Data from the hook arrives here.
    Finish: func(w http.ResponseWriter, r *http.Request, redirectTo string, l session.Login) {
        http.Redirect(w, r, redirectTo, http.StatusFound)
    },
})
mux.Handle("GET /login", h.Login())
mux.Handle("GET /auth/callback", h.Callback())
mux.Handle("POST /logout", h.Logout())
```

`Login` (and `Register`, which lands on the IdP's registration page) reuse a flow
already in progress, so two tabs do not invalidate each other. `Callback`
rejects an upstream error, a missing code or state, a state that does not match
the flow cookie (compared in constant time) and a missing verifier, all before
the code is exchanged; then it exchanges with PKCE, runs `OnAuthenticated`,
starts the session and clears the flow cookies, then redirects or, when `Finish`
is set, hands the response to it with the sanitized target and the hook's `Data`. Failure responses are generic;
the detail goes to `Logf`. The post-login redirect is reduced to a local path
(`oidclient.LocalPath`) both when `Login` stores it and when `Callback` reads it
back, since the cookie can be planted from a sibling subdomain.

`Logout` accepts POST only, because a state-changing GET can be triggered by any
page the user visits. Render sign-out as a form.

### Provisioning local users

The `oidclient/rpuser` subpackage is the audited claims -> local-user path, so
relying parties don't each re-implement the post-login sync policy: users are
keyed strictly on (issuer, subject) and never matched by email, mutable claims
(email, email_verified) sync at login only, and the per-request path is
read-only. The host keeps its schema and SQL, implementing `rpuser.UserStore`
over its own users table; the package owns the flow.

```go
store := myUserStore{}  // implements rpuser.UserStore over the host DB
prov := &rpuser.Provisioner{Store: store, Issuer: cfg.IssuerURL}
mw := &rpuser.Middleware{Authenticator: mgr, Store: store, Issuer: cfg.IssuerURL}

// callback, after Exchange:  u, isNew, err := prov.Provision(ctx, claims)
// route setup:               handler = mw.Optional(mux)
// in handlers:               rpuser.UserFromContext(ctx), rpuser.IdentityFromContext(ctx)
```

`rpuser.Identity` mirrors `authz.Identity` and carries no roles: authorization
is resolved by the host's grant store (see
[infodancer/authz](https://github.com/infodancer/authz)), never from claims.
Rationale: [issue #10](https://github.com/infodancer/oidclient/issues/10).

## License

Apache-2.0 — see [LICENSE](LICENSE). Vulnerability reporting in
[SECURITY.md](SECURITY.md).
