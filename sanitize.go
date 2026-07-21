package oidclient

import (
	"net/url"
	"strings"
)

// LocalPath returns p when p is a relative same-origin path safe to hand to
// http.Redirect after the OIDC flow, or "" otherwise. It rejects:
//
//   - absolute URLs (http://evil/, https://evil/),
//   - protocol-relative URLs (//evil/path),
//   - backslash-prefixed variants (/\evil/path) that some browsers
//     historically normalised into a network-path reference,
//   - anything parsing into a URL with a non-empty Scheme or Host.
//
// Use it both where a redirect destination is first accepted (e.g. a login
// handler's "return" query parameter) and where it is read back (a
// CallbackOptions.SanitizeRedirect implementation, or the equivalent point in
// a hand-rolled callback handler) -- validating only one side leaves an
// opening for a redirect cookie planted out of band, e.g. from a compromised
// sibling subdomain.
func LocalPath(p string) string {
	if p == "" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		return ""
	}
	if strings.HasPrefix(p, "//") || strings.HasPrefix(p, "/\\") {
		return ""
	}
	u, err := url.Parse(p)
	if err != nil {
		return ""
	}
	if u.Scheme != "" || u.Host != "" {
		return ""
	}
	return p
}
