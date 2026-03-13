package oidclient

import (
	"crypto/rand"
	"encoding/base64"

	"golang.org/x/oauth2"
)

// GenerateVerifier returns a random PKCE code verifier (RFC 7636).
// The verifier should be stored (e.g. in a cookie) and passed to both
// AuthorizeURL and ExchangeCode.
func GenerateVerifier() string {
	return oauth2.GenerateVerifier()
}

// GenerateNonce returns a random base64url-encoded state nonce for CSRF protection.
func GenerateNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
