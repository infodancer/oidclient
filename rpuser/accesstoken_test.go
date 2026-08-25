package rpuser

import (
	"context"
	"errors"
	"testing"

	"github.com/infodancer/oidclient"
)

const rsTestIssuer = "https://webauth.example.test/t/memstore"

// FromAccessToken is the resource-server counterpart of FromClaims. Both must
// normalize to the same Identity, because the provisioning policy below them
// keys on it -- if the two paths disagreed about how a subject or a display
// name is derived, the same person arriving over each would provision twice.
func TestFromAccessTokenMatchesFromClaims(t *testing.T) {
	claims := &oidclient.Claims{
		Sub:           "sub-abc",
		Email:         "someone@example.test",
		EmailVerified: true,
		Name:          "Someone",
	}
	tok := &oidclient.AccessToken{
		Subject:       "sub-abc",
		Email:         "someone@example.test",
		EmailVerified: true,
		Name:          "Someone",
	}

	if got, want := FromAccessToken(rsTestIssuer, tok), FromClaims(rsTestIssuer, claims); got != want {
		t.Errorf("FromAccessToken = %+v, FromClaims = %+v; want identical", got, want)
	}
}

// The display-name fallback is the one policy FromClaims owns, so the access
// token path has to apply it too rather than leaving the name empty.
func TestFromAccessTokenAppliesDisplayNameFallback(t *testing.T) {
	id := FromAccessToken(rsTestIssuer, &oidclient.AccessToken{
		Subject: "sub-abc",
		Email:   "someone@example.test",
	})
	if id.DisplayName != "someone@example.test" {
		t.Errorf("DisplayName = %q, want the email as fallback", id.DisplayName)
	}
}

func TestFromAccessTokenUsesTheConfiguredIssuer(t *testing.T) {
	id := FromAccessToken(rsTestIssuer, &oidclient.AccessToken{Subject: "sub-abc"})
	if id.Issuer != rsTestIssuer {
		t.Errorf("Issuer = %q, want %q", id.Issuer, rsTestIssuer)
	}
}

// --- ProvisionIdentity ------------------------------------------------------

type memStore struct {
	users   map[string]User // keyed issuer+"\x00"+subject
	creates int
	syncs   int
	lastID  Identity
	failNow error
}

func newMemStore() *memStore { return &memStore{users: map[string]User{}} }

func key(issuer, subject string) string { return issuer + "\x00" + subject }

func (s *memStore) LookupBySubject(_ context.Context, issuer, subject string) (User, error) {
	if s.failNow != nil {
		return User{}, s.failNow
	}
	u, ok := s.users[key(issuer, subject)]
	if !ok {
		return User{}, ErrNotFound
	}
	return u, nil
}

func (s *memStore) SyncEmail(_ context.Context, userKey, email string, verified bool) error {
	s.syncs++
	for k, u := range s.users {
		if u.Key == userKey {
			u.Email, u.EmailVerified = email, verified
			s.users[k] = u
			return nil
		}
	}
	return errors.New("no such user")
}

func (s *memStore) Create(_ context.Context, id Identity) (User, error) {
	s.creates++
	s.lastID = id
	// Keyed on the pair, as a real store must be: a subject string is only
	// unique within its issuer.
	u := User{Key: "u-" + id.Issuer + "-" + id.Subject, Email: id.Email, EmailVerified: id.EmailVerified}
	s.users[key(id.Issuer, id.Subject)] = u
	return u, nil
}

// The whole point of splitting ProvisionIdentity out is that a resource server,
// which never sees an oidclient.Claims, gets the identical policy: create on
// first sight of a subject, and never a second row for one already known.
func TestProvisionIdentityCreatesThenReuses(t *testing.T) {
	store := newMemStore()
	p := &Provisioner{Store: store, Issuer: rsTestIssuer}
	id := FromAccessToken(rsTestIssuer, &oidclient.AccessToken{
		Subject: "sub-abc", Email: "someone@example.test", EmailVerified: true,
	})

	u1, created, err := p.ProvisionIdentity(context.Background(), id)
	if err != nil {
		t.Fatalf("ProvisionIdentity: %v", err)
	}
	if !created {
		t.Error("first call reported the user as pre-existing")
	}

	u2, created, err := p.ProvisionIdentity(context.Background(), id)
	if err != nil {
		t.Fatalf("ProvisionIdentity (second): %v", err)
	}
	if created {
		t.Error("second call created a second row for a known subject")
	}
	if u1.Key != u2.Key {
		t.Errorf("keys differ across calls: %q then %q", u1.Key, u2.Key)
	}
	if store.creates != 1 {
		t.Errorf("Create called %d times, want 1", store.creates)
	}
}

// Never match or merge by email: an upstream that recycles an address must not
// hand its new owner someone else's account. Two subjects with one email are
// two users.
func TestProvisionIdentityNeverMergesByEmail(t *testing.T) {
	store := newMemStore()
	p := &Provisioner{Store: store, Issuer: rsTestIssuer}
	shared := "recycled@example.test"

	first, _, err := p.ProvisionIdentity(context.Background(),
		FromAccessToken(rsTestIssuer, &oidclient.AccessToken{Subject: "sub-old", Email: shared}))
	if err != nil {
		t.Fatalf("ProvisionIdentity: %v", err)
	}
	second, created, err := p.ProvisionIdentity(context.Background(),
		FromAccessToken(rsTestIssuer, &oidclient.AccessToken{Subject: "sub-new", Email: shared}))
	if err != nil {
		t.Fatalf("ProvisionIdentity: %v", err)
	}

	if !created {
		t.Error("a new subject sharing an email was matched to the existing account")
	}
	if first.Key == second.Key {
		t.Errorf("two subjects sharing an email resolved to one user %q", first.Key)
	}
}

// A subject that is the same string at a different issuer is a different
// person. The key is the pair, not the subject alone.
func TestProvisionIdentityScopesSubjectsToTheIssuer(t *testing.T) {
	store := newMemStore()
	a := &Provisioner{Store: store, Issuer: "https://a.example.test"}
	b := &Provisioner{Store: store, Issuer: "https://b.example.test"}

	ua, _, err := a.ProvisionIdentity(context.Background(),
		FromAccessToken("https://a.example.test", &oidclient.AccessToken{Subject: "1"}))
	if err != nil {
		t.Fatalf("ProvisionIdentity: %v", err)
	}
	ub, created, err := b.ProvisionIdentity(context.Background(),
		FromAccessToken("https://b.example.test", &oidclient.AccessToken{Subject: "1"}))
	if err != nil {
		t.Fatalf("ProvisionIdentity: %v", err)
	}
	if !created || ua.Key == ub.Key {
		t.Errorf("subject 1 at two issuers resolved to the same user (%q, %q)", ua.Key, ub.Key)
	}
}

// A lookup failure that is not "no such user" must abort rather than fall
// through to Create, which would insert a duplicate row every time the database
// was unhealthy.
func TestProvisionIdentityDoesNotCreateOnLookupFailure(t *testing.T) {
	store := newMemStore()
	store.failNow = errors.New("connection refused")
	p := &Provisioner{Store: store, Issuer: rsTestIssuer}

	if _, _, err := p.ProvisionIdentity(context.Background(),
		FromAccessToken(rsTestIssuer, &oidclient.AccessToken{Subject: "sub-abc"})); err == nil {
		t.Fatal("ProvisionIdentity succeeded despite a failing lookup")
	}
	if store.creates != 0 {
		t.Errorf("Create was called %d times after a lookup failure", store.creates)
	}
}

// Provision must remain exactly ProvisionIdentity over FromClaims, so the
// relying-party path is unchanged by the split.
func TestProvisionStillDelegatesToProvisionIdentity(t *testing.T) {
	store := newMemStore()
	p := &Provisioner{Store: store, Issuer: rsTestIssuer}

	if _, _, err := p.Provision(context.Background(), &oidclient.Claims{
		Sub: "sub-abc", Email: "someone@example.test", EmailVerified: true,
	}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	// The same person over the resource-server path must find that row, not
	// make another.
	_, created, err := p.ProvisionIdentity(context.Background(),
		FromAccessToken(rsTestIssuer, &oidclient.AccessToken{
			Subject: "sub-abc", Email: "someone@example.test", EmailVerified: true,
		}))
	if err != nil {
		t.Fatalf("ProvisionIdentity: %v", err)
	}
	if created {
		t.Error("the resource-server path created a second row for a user provisioned over the RP path")
	}
}
