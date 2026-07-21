package oidclient

import "testing"

// TestLocalPath walks the open-redirect attack surface. LocalPath is the
// only gate between an attacker-supplied ?return= query parameter (or cookie
// value) and an http.Redirect destination -- any false-positive here turns an
// OIDC login flow into a phishing jump-off point.
func TestLocalPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		// Legitimate same-origin paths.
		{"root", "/", "/"},
		{"deep path", "/articles/42", "/articles/42"},
		{"with query", "/articles?feed_id=1", "/articles?feed_id=1"},
		{"with fragment", "/page#anchor", "/page#anchor"},
		{"with percent-encoded", "/u/space%20name", "/u/space%20name"},

		// Empty / missing.
		{"empty", "", ""},

		// Absolute URLs -- the classic open-redirect payload.
		{"absolute https", "https://evil.example/profile", ""},
		{"absolute http", "http://evil.example/profile", ""},
		{"javascript scheme", "javascript:alert(1)", ""},
		{"data scheme", "data:text/html,evil", ""},

		// Protocol-relative -- most common bypass after the scheme check.
		{"protocol-relative", "//evil.example/profile", ""},
		{"protocol-relative bare", "//evil.example", ""},

		// Backslash variants -- historically normalised by some
		// browsers into a network-path reference.
		{"backslash after slash", "/\\evil.example/profile", ""},

		// Doesn't start with /.
		{"bare path", "articles/42", ""},
		{"relative dotdot", "../etc/passwd", ""},

		// Weird but plausible mangling that must still be rejected.
		{"whitespace prefix", " /articles", ""},
		{"tab prefix", "\t/articles", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := LocalPath(tc.in); got != tc.want {
				t.Fatalf("LocalPath(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
