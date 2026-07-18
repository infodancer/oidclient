package rpuser

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/infodancer/oidclient"
)

const testIssuer = "https://auth.example.com"

// fakeStore is an in-memory UserStore that records every mutating call, so
// tests can assert both outcomes and which store operations ran (the
// login-only sync policy makes "no write happened" a meaningful assertion).
type fakeStore struct {
	users map[string]User // keyed issuer + "|" + subject

	syncCalls   []syncCall
	createCalls []Identity

	lookupErr error
	syncErr   error
	createErr error
}

type syncCall struct {
	key      string
	email    string
	verified bool
}

func newFakeStore() *fakeStore {
	return &fakeStore{users: map[string]User{}}
}

func (f *fakeStore) put(issuer, subject string, u User) {
	f.users[issuer+"|"+subject] = u
}

func (f *fakeStore) LookupBySubject(_ context.Context, issuer, subject string) (User, error) {
	if f.lookupErr != nil {
		return User{}, f.lookupErr
	}
	u, ok := f.users[issuer+"|"+subject]
	if !ok {
		return User{}, ErrNotFound
	}
	return u, nil
}

func (f *fakeStore) SyncEmail(_ context.Context, key, email string, verified bool) error {
	f.syncCalls = append(f.syncCalls, syncCall{key: key, email: email, verified: verified})
	return f.syncErr
}

func (f *fakeStore) Create(_ context.Context, id Identity) (User, error) {
	f.createCalls = append(f.createCalls, id)
	if f.createErr != nil {
		return User{}, f.createErr
	}
	u := User{Key: fmt.Sprintf("u%d", len(f.createCalls)), Email: id.Email, EmailVerified: id.EmailVerified}
	f.put(id.Issuer, id.Subject, u)
	return u, nil
}

func TestFromClaims(t *testing.T) {
	c := &oidclient.Claims{Sub: "sub-1", Email: "a@example.com", EmailVerified: true, Name: "Alice"}
	id := FromClaims(testIssuer, c)

	want := Identity{
		Issuer:        testIssuer,
		Subject:       "sub-1",
		DisplayName:   "Alice",
		Email:         "a@example.com",
		EmailVerified: true,
	}
	if id != want {
		t.Errorf("FromClaims = %+v, want %+v", id, want)
	}
}

func TestFromClaims_DisplayNameFallsBackToEmail(t *testing.T) {
	c := &oidclient.Claims{Sub: "sub-1", Email: "a@example.com"}
	id := FromClaims(testIssuer, c)
	if id.DisplayName != "a@example.com" {
		t.Errorf("DisplayName = %q, want fallback to email", id.DisplayName)
	}
}

func TestProvision_FirstLoginCreates(t *testing.T) {
	st := newFakeStore()
	p := &Provisioner{Store: st, Issuer: testIssuer}

	u, created, err := p.Provision(context.Background(), &oidclient.Claims{
		Sub: "sub-new", Email: "new@example.com", EmailVerified: true,
	})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if !created {
		t.Error("created = false, want true for a first login")
	}
	if u.Key == "" {
		t.Error("Provision returned an empty user key")
	}
	if len(st.createCalls) != 1 {
		t.Fatalf("Create called %d times, want 1", len(st.createCalls))
	}
	// The identity handed to Create must be fully normalized: issuer injected,
	// display name fallback applied.
	got := st.createCalls[0]
	if got.Issuer != testIssuer {
		t.Errorf("Create identity issuer = %q, want %q", got.Issuer, testIssuer)
	}
	if got.DisplayName != "new@example.com" {
		t.Errorf("Create identity display name = %q, want email fallback", got.DisplayName)
	}
}

func TestProvision_ExistingUserNoWrites(t *testing.T) {
	st := newFakeStore()
	st.put(testIssuer, "sub-1", User{Key: "u1", Email: "a@example.com", EmailVerified: true})
	p := &Provisioner{Store: st, Issuer: testIssuer}

	u, created, err := p.Provision(context.Background(), &oidclient.Claims{
		Sub: "sub-1", Email: "a@example.com", EmailVerified: true,
	})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if created {
		t.Error("created = true for an existing user")
	}
	if u.Key != "u1" {
		t.Errorf("user key = %q, want u1", u.Key)
	}
	if len(st.syncCalls) != 0 || len(st.createCalls) != 0 {
		t.Errorf("unchanged claims caused writes: syncs=%d creates=%d", len(st.syncCalls), len(st.createCalls))
	}
}

func TestProvision_SyncsChangedEmail(t *testing.T) {
	st := newFakeStore()
	st.put(testIssuer, "sub-1", User{Key: "u1", Email: "old@example.com", EmailVerified: true})
	p := &Provisioner{Store: st, Issuer: testIssuer}

	u, _, err := p.Provision(context.Background(), &oidclient.Claims{
		Sub: "sub-1", Email: "new@example.com", EmailVerified: true,
	})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if len(st.syncCalls) != 1 {
		t.Fatalf("SyncEmail called %d times, want 1", len(st.syncCalls))
	}
	want := syncCall{key: "u1", email: "new@example.com", verified: true}
	if st.syncCalls[0] != want {
		t.Errorf("SyncEmail = %+v, want %+v", st.syncCalls[0], want)
	}
	// The returned user reflects the synced values.
	if u.Email != "new@example.com" {
		t.Errorf("returned user email = %q, want synced value", u.Email)
	}
}

func TestProvision_SyncsVerifiedFlip(t *testing.T) {
	st := newFakeStore()
	st.put(testIssuer, "sub-1", User{Key: "u1", Email: "a@example.com", EmailVerified: false})
	p := &Provisioner{Store: st, Issuer: testIssuer}

	u, _, err := p.Provision(context.Background(), &oidclient.Claims{
		Sub: "sub-1", Email: "a@example.com", EmailVerified: true,
	})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if len(st.syncCalls) != 1 {
		t.Fatalf("SyncEmail called %d times, want 1", len(st.syncCalls))
	}
	if !st.syncCalls[0].verified {
		t.Error("SyncEmail verified = false, want true")
	}
	if !u.EmailVerified {
		t.Error("returned user EmailVerified = false, want true")
	}
}

func TestProvision_EmptyClaimEmailDoesNotClobber(t *testing.T) {
	st := newFakeStore()
	st.put(testIssuer, "sub-1", User{Key: "u1", Email: "keep@example.com", EmailVerified: false})
	p := &Provisioner{Store: st, Issuer: testIssuer}

	// Empty email claim with a verified flip: the flip must sync but the stored
	// email must survive.
	_, _, err := p.Provision(context.Background(), &oidclient.Claims{
		Sub: "sub-1", EmailVerified: true,
	})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if len(st.syncCalls) != 1 {
		t.Fatalf("SyncEmail called %d times, want 1", len(st.syncCalls))
	}
	if st.syncCalls[0].email != "keep@example.com" {
		t.Errorf("SyncEmail email = %q, want stored email preserved", st.syncCalls[0].email)
	}
}

func TestProvision_PreCreateAdopts(t *testing.T) {
	st := newFakeStore()
	adopted := User{Key: "seed-9", Email: "a@example.com", EmailVerified: true}
	p := &Provisioner{
		Store:  st,
		Issuer: testIssuer,
		PreCreate: func(_ context.Context, id Identity) (User, bool, error) {
			return adopted, true, nil
		},
	}

	u, created, err := p.Provision(context.Background(), &oidclient.Claims{
		Sub: "sub-1", Email: "a@example.com", EmailVerified: true,
	})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if created {
		t.Error("created = true for an adoption, want false")
	}
	if u.Key != "seed-9" {
		t.Errorf("user key = %q, want the adopted account", u.Key)
	}
	if len(st.createCalls) != 0 {
		t.Errorf("Create called %d times after adoption, want 0", len(st.createCalls))
	}
}

func TestProvision_PreCreateDeclines(t *testing.T) {
	st := newFakeStore()
	p := &Provisioner{
		Store:  st,
		Issuer: testIssuer,
		PreCreate: func(_ context.Context, _ Identity) (User, bool, error) {
			return User{}, false, nil
		},
	}

	_, created, err := p.Provision(context.Background(), &oidclient.Claims{Sub: "sub-1", Email: "a@example.com"})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if !created {
		t.Error("created = false, want true when PreCreate declines")
	}
	if len(st.createCalls) != 1 {
		t.Errorf("Create called %d times, want 1", len(st.createCalls))
	}
}

func TestProvision_PreCreateError(t *testing.T) {
	st := newFakeStore()
	boom := errors.New("adoption failed")
	p := &Provisioner{
		Store:  st,
		Issuer: testIssuer,
		PreCreate: func(_ context.Context, _ Identity) (User, bool, error) {
			return User{}, false, boom
		},
	}

	_, _, err := p.Provision(context.Background(), &oidclient.Claims{Sub: "sub-1"})
	if !errors.Is(err, boom) {
		t.Errorf("Provision error = %v, want the PreCreate error", err)
	}
	if len(st.createCalls) != 0 {
		t.Error("Create ran despite a PreCreate error")
	}
}

func TestProvision_LookupErrorPropagates(t *testing.T) {
	st := newFakeStore()
	st.lookupErr = errors.New("db down")
	p := &Provisioner{Store: st, Issuer: testIssuer}

	_, _, err := p.Provision(context.Background(), &oidclient.Claims{Sub: "sub-1"})
	if err == nil || !strings.Contains(err.Error(), "db down") {
		t.Errorf("Provision error = %v, want the lookup error", err)
	}
	if len(st.createCalls) != 0 {
		t.Error("Create ran despite a lookup error")
	}
}

func TestProvision_CreateErrorPropagates(t *testing.T) {
	st := newFakeStore()
	st.createErr = errors.New("insert failed")
	p := &Provisioner{Store: st, Issuer: testIssuer}

	_, _, err := p.Provision(context.Background(), &oidclient.Claims{Sub: "sub-1"})
	if err == nil || !strings.Contains(err.Error(), "insert failed") {
		t.Errorf("Provision error = %v, want the create error", err)
	}
}

func TestProvision_SyncErrorIsBestEffort(t *testing.T) {
	st := newFakeStore()
	st.put(testIssuer, "sub-1", User{Key: "u1", Email: "old@example.com"})
	st.syncErr = errors.New("update failed")
	var logged []string
	p := &Provisioner{
		Store:  st,
		Issuer: testIssuer,
		Logf:   func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) },
	}

	u, _, err := p.Provision(context.Background(), &oidclient.Claims{Sub: "sub-1", Email: "new@example.com"})
	if err != nil {
		t.Fatalf("Provision failed on a best-effort sync error: %v", err)
	}
	// The failed sync must not pretend it succeeded: the returned user keeps
	// the stored values, and the failure is logged.
	if u.Email != "old@example.com" {
		t.Errorf("returned user email = %q after failed sync, want stored value", u.Email)
	}
	if len(logged) == 0 {
		t.Error("failed sync was not logged")
	}
}

func TestProvision_NilClaims(t *testing.T) {
	p := &Provisioner{Store: newFakeStore(), Issuer: testIssuer}
	if _, _, err := p.Provision(context.Background(), nil); err == nil {
		t.Error("Provision(nil claims) = nil error, want error")
	}
}
