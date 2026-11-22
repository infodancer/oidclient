package session

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/infodancer/oidclient"
)

// recheckRenewer validates the stored token to claims issued at iat, and
// refreshes to a token whose claims carry verified.
func recheckRenewer(iat time.Time, refreshErr error) *fakeRenewer {
	return &fakeRenewer{
		validate: func(tok string) (*oidclient.Claims, error) {
			if tok == "fresh-at" {
				return &oidclient.Claims{Sub: "user-1", EmailVerified: true, Iat: time.Now().Unix()}, nil
			}
			return &oidclient.Claims{Sub: "user-1", Iat: iat.Unix()}, nil
		},
		refresh: func(string) (*oidclient.Tokens, *oidclient.Claims, error) {
			if refreshErr != nil {
				return nil, nil, refreshErr
			}
			return &oidclient.Tokens{AccessToken: "fresh-at", RefreshToken: "rt-new", Expiry: time.Now().Add(time.Hour)},
				&oidclient.Claims{Sub: "user-1", EmailVerified: true, Iat: time.Now().Unix()}, nil
		},
	}
}

// A token that is still valid but older than the interval is renewed early, so
// a change at the provider reaches the session without waiting out the token.
func TestRecheck_RenewsATokenOlderThanTheInterval(t *testing.T) {
	store, kr := newMemStore(), testKeyring(t)
	seed(t, store, kr, "sid", "old-at", "rt-1", time.Now().Add(23*time.Hour), time.Now().Add(24*time.Hour), 0)
	ren := recheckRenewer(time.Now().Add(-time.Hour), nil)
	m := newManager(t, store, ren, kr)

	claims, err := m.Recheck(reqCookie("sid"), 5*time.Minute)
	if err != nil {
		t.Fatalf("Recheck: %v", err)
	}
	if !claims.EmailVerified {
		t.Error("claims are the stored ones, want the renewed ones")
	}
	if ren.refreshN != 1 {
		t.Errorf("refreshN = %d, want 1", ren.refreshN)
	}
	if at, _ := kr.Open(store.rows["sid"].AccessToken, []byte("sid")); string(at) != "fresh-at" {
		t.Errorf("stored access token = %q, want the rotated one persisted", at)
	}
}

// A token issued inside the interval is already as fresh as the caller asked
// for: no grant is spent.
func TestRecheck_LeavesARecentTokenAlone(t *testing.T) {
	store, kr := newMemStore(), testKeyring(t)
	seed(t, store, kr, "sid", "old-at", "rt-1", time.Now().Add(23*time.Hour), time.Now().Add(24*time.Hour), 0)
	ren := recheckRenewer(time.Now().Add(-time.Minute), nil)
	m := newManager(t, store, ren, kr)

	claims, err := m.Recheck(reqCookie("sid"), 5*time.Minute)
	if err != nil {
		t.Fatalf("Recheck: %v", err)
	}
	if claims.EmailVerified || ren.refreshN != 0 {
		t.Errorf("refreshN = %d, verified = %v; want the stored claims and no refresh", ren.refreshN, claims.EmailVerified)
	}
}

// The interval bounds attempts, not successes. A provider that keeps failing,
// or a token with no iat to judge by, must cost one grant per interval and not
// one per request.
func TestRecheck_ThrottlesAttempts(t *testing.T) {
	for _, tc := range []struct {
		name       string
		iat        time.Time
		refreshErr error
	}{
		{"failing provider", time.Now().Add(-time.Hour), errors.New("provider down")},
		{"token without iat", time.Unix(0, 0), errors.New("provider down")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, kr := newMemStore(), testKeyring(t)
			seed(t, store, kr, "sid", "old-at", "rt-1", time.Now().Add(23*time.Hour), time.Now().Add(24*time.Hour), 0)
			ren := recheckRenewer(tc.iat, tc.refreshErr)
			m := newManager(t, store, ren, kr)

			if _, err := m.Recheck(reqCookie("sid"), 5*time.Minute); err == nil {
				t.Fatal("first Recheck: want the refresh failure reported")
			}
			for range 5 {
				claims, err := m.Recheck(reqCookie("sid"), 5*time.Minute)
				if err != nil || claims == nil || claims.Sub != "user-1" {
					t.Fatalf("throttled Recheck = %v, %v; want the stored claims", claims, err)
				}
			}
			if ren.refreshN != 1 {
				t.Errorf("refreshN = %d, want 1 attempt inside the interval", ren.refreshN)
			}
		})
	}
}

// A failed early renewal must not cost the user a session whose token is
// still good: Authenticate keeps working.
func TestRecheck_FailureLeavesTheSessionUsable(t *testing.T) {
	store, kr := newMemStore(), testKeyring(t)
	seed(t, store, kr, "sid", "old-at", "rt-1", time.Now().Add(23*time.Hour), time.Now().Add(24*time.Hour), 0)
	m := newManager(t, store, recheckRenewer(time.Now().Add(-time.Hour), errors.New("provider down")), kr)

	if _, err := m.Recheck(reqCookie("sid"), 5*time.Minute); err == nil {
		t.Fatal("want the refresh failure reported")
	}
	if claims, err := m.Authenticate(reqCookie("sid")); err != nil || claims.Sub != "user-1" {
		t.Errorf("Authenticate after a failed recheck = %v, %v; want the stored claims", claims, err)
	}
	if _, ok := store.rows["sid"]; !ok {
		t.Error("session row was deleted by a failed recheck")
	}
}

func TestRecheck_NoSession(t *testing.T) {
	m := newManager(t, newMemStore(), recheckRenewer(time.Now(), nil), testKeyring(t))
	if _, err := m.Recheck(reqCookie(""), time.Minute); !errors.Is(err, ErrNoSession) {
		t.Errorf("no cookie: %v, want ErrNoSession", err)
	}
	if _, err := m.Recheck(reqCookie("ghost"), time.Minute); !errors.Is(err, ErrNoSession) {
		t.Errorf("unknown session: %v, want ErrNoSession", err)
	}
}

// A non-positive interval would mean "renew on every request".
func TestRecheck_RejectsANonPositiveInterval(t *testing.T) {
	store, kr := newMemStore(), testKeyring(t)
	seed(t, store, kr, "sid", "old-at", "rt-1", time.Now().Add(23*time.Hour), time.Now().Add(24*time.Hour), 0)
	ren := recheckRenewer(time.Now().Add(-time.Hour), nil)
	m := newManager(t, store, ren, kr)
	if _, err := m.Recheck(reqCookie("sid"), 0); err == nil {
		t.Error("want an error for a zero interval")
	}
	if ren.refreshN != 0 {
		t.Errorf("refreshN = %d, want 0", ren.refreshN)
	}
}

// The attempt record must not grow without bound across many sessions.
func TestRecheck_AttemptRecordIsPruned(t *testing.T) {
	store, kr := newMemStore(), testKeyring(t)
	m := newManager(t, store, recheckRenewer(time.Now().Add(-time.Hour), errors.New("provider down")), kr)
	for i := range recheckPruneAt + 50 {
		m.rechecks.allow("s"+string(rune('a'+i%26))+time.Duration(i).String(), time.Now().Add(-time.Hour), time.Minute)
	}
	m.rechecks.allow("last", time.Now(), time.Minute)
	if n := m.rechecks.len(); n > 51 {
		t.Errorf("attempt record holds %d entries after pruning, want only the unexpired ones", n)
	}
}

// Parallel requests on one session share one early renewal: the provider
// rotates the refresh token on use, so two grants would trip replay detection.
func TestRecheck_ConcurrentRequestsSpendOneGrant(t *testing.T) {
	store, kr := newMemStore(), testKeyring(t)
	seed(t, store, kr, "sid", "old-at", "rt-1", time.Now().Add(23*time.Hour), time.Now().Add(24*time.Hour), 0)
	ren := recheckRenewer(time.Now().Add(-time.Hour), nil)
	m := newManager(t, store, ren, kr)

	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := m.Recheck(reqCookie("sid"), 5*time.Minute); err != nil {
				t.Errorf("Recheck: %v", err)
			}
		}()
	}
	wg.Wait()
	if ren.refreshN != 1 {
		t.Errorf("refreshN = %d, want 1", ren.refreshN)
	}
}
