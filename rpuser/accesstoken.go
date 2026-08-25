package rpuser

import (
	"context"

	"github.com/infodancer/oidclient"
)

// The resource-server half of this package.
//
// [Provisioner.Provision] takes the claims of a completed login, which is the
// relying-party shape. A resource server never has one: it validates a bearer
// token it did not obtain and gets an [oidclient.AccessToken]. The policy it
// needs is identical, so the policy is expressed over [Identity] and both
// paths normalize into it.
//
// Keeping them on one policy is not tidiness. The same person may reach a host
// both ways -- signing in to its web UI and calling its API from a tool -- and
// if the two paths derived the key differently they would provision two
// accounts for one human, each holding half their data.

// FromAccessToken normalizes a verified access token into an [Identity]. It is
// the counterpart of [FromClaims] and applies the same display-name fallback.
//
// issuer is the resource server's configured issuer URL, which oidclient has
// already validated the token's iss against during verification -- so the
// configured value is the authoritative string, not a claim read back out of
// the token.
func FromAccessToken(issuer string, t *oidclient.AccessToken) Identity {
	if t == nil {
		return Identity{Issuer: issuer}
	}
	name := t.Name
	if name == "" {
		name = t.Email
	}
	return Identity{
		Issuer:        issuer,
		Subject:       t.Subject,
		DisplayName:   name,
		Email:         t.Email,
		EmailVerified: t.EmailVerified,
	}
}

// ProvisionAccessToken returns the local user for a verified access token,
// creating one on first sight of its subject. It is [Provisioner.Provision]
// for the resource-server path.
func (p *Provisioner) ProvisionAccessToken(ctx context.Context, t *oidclient.AccessToken) (User, bool, error) {
	return p.ProvisionIdentity(ctx, FromAccessToken(p.Issuer, t))
}
