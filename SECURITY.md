# Security policy

## Reporting a vulnerability

Report privately via [GitHub's private vulnerability reporting][gh-pvr]
for this repository. As a fallback, you can email
matthewjayhunter@gmail.com with the subject line `[oidclient security]
<short description>`. Use PGP if you'd like — keys on keys.openpgp.org
under that address.

[gh-pvr]: https://github.com/infodancer/oidclient/security/advisories/new

This is a personal/internal-use library maintained on nights and
weekends; please don't expect commercial-grade response times, but I
will take credible reports seriously, especially anything that bypasses
token validation or leaks credentials.

## In scope

- The `Client.Validate` and `Client.ExchangeCode` paths: signature
  verification bypass, issuer/audience confusion, expiry checks,
  algorithm confusion attacks (none/HS256 substitution against an
  RS256-expecting verifier).
- PKCE handling in `AuthorizeURL`, `RegisterURL`, and `ExchangeCode`:
  verifier/challenge correctness per RFC 7636, weak entropy in
  `GenerateVerifier` or `GenerateNonce`.
- Cookie helpers in `cookie.go`: `Secure`/`HttpOnly`/`SameSite` defaults,
  expiration handling, scope correctness, susceptibility to
  fixation/replay through the flow cookies.
- Dynamic client registration (`autoRegister`): credential exposure,
  unintended registration of attacker-controlled redirect URIs.

Out of band: cryptographic primitives are delegated to
[`coreos/go-oidc`][go-oidc] and [`go-jose`][go-jose]. Report flaws in
those libraries to their upstreams; I track CVE advisories and will
bump dependencies.

[go-oidc]: https://github.com/coreos/go-oidc
[go-jose]: https://github.com/go-jose/go-jose

## Out of scope

- Issues that require an attacker to already control the IdP
  (`IssuerURL`), the application's session storage, or the user's
  cookie jar.
- Misconfiguration in the consuming application: missing TLS, using
  this library against an unverified issuer, exposing tokens in logs,
  bypassing `ValidateCookie` on protected handlers.
- Behavior changes in upstream `coreos/go-oidc` or `golang.org/x/oauth2`
  — please report those upstream.
- The strength of any individual IdP's tenant/role model. This library
  validates the JWT and extracts claims; authorization decisions are
  the consumer's responsibility.
