package session

import (
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/infodancer/oidclient"
)

// recheckPruneAt is the size at which the attempt record sheds expired
// entries. Only sessions that are being rechecked are recorded, and each entry
// expires after one interval, so the record stays near the number of such
// sessions active inside an interval.
const recheckPruneAt = 1024

// Recheck is [Manager.Authenticate] for a caller that needs claims no older
// than minInterval: it renews the access token early when the stored one,
// though still valid, was issued longer ago than that. The provider re-reads
// the user on a refresh-token grant, so this is how a change made there since
// sign-in reaches a live session without waiting out the token.
//
// It spends at most one grant per session per minInterval, counting attempts
// and not successes: a provider that is failing, or a token with no iat to
// judge its age by, costs one grant per interval and not one per request.
// Inside the interval it returns the stored claims. Cost is the reason to call
// it only for the sessions that need it; Authenticate is the general path.
//
// A failed early renewal is returned as an error and leaves the session as it
// was -- the stored token is still good, and Authenticate keeps accepting it.
// minInterval must be positive.
func (m *Manager) Recheck(r *http.Request, minInterval time.Duration) (*oidclient.Claims, error) {
	if minInterval <= 0 {
		return nil, errors.New("oidclient/session: Recheck needs a positive interval")
	}
	sess, err := m.load(r)
	if err != nil {
		return nil, err
	}
	stored, ok := m.tryStoredAccessToken(r.Context(), sess)
	if !ok {
		// Expired or unusable: the ordinary renewal, not an early one.
		return m.renew(sess, nil)
	}
	now := time.Now()
	if issuedWithin(stored, now, minInterval) || !m.rechecks.allow(sess.ID, now, minInterval) {
		return stored, nil
	}
	return m.renew(sess, func(c *oidclient.Claims) bool {
		return issuedWithin(c, time.Now(), minInterval)
	})
}

// issuedWithin reports whether the claims carry an iat no further than d
// before now. Claims without an iat are of unknown age and never qualify.
func issuedWithin(c *oidclient.Claims, now time.Time, d time.Duration) bool {
	return c.Iat != 0 && now.Sub(c.IssuedAt()) <= d
}

// recheckLog remembers, per session id, the time before which another early
// renewal may not be attempted. It is per process: several instances each keep
// their own, so a session can cost one grant per instance per interval.
type recheckLog struct {
	mu    sync.Mutex
	until map[string]time.Time
}

// allow reports whether an attempt for id may run at now, and if so records it
// so that no other runs for the next interval.
func (l *recheckLog) allow(id string, now time.Time, interval time.Duration) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if t, ok := l.until[id]; ok && now.Before(t) {
		return false
	}
	if l.until == nil {
		l.until = make(map[string]time.Time)
	}
	if len(l.until) >= recheckPruneAt {
		for k, t := range l.until {
			if !now.Before(t) {
				delete(l.until, k)
			}
		}
	}
	l.until[id] = now.Add(interval)
	return true
}

func (l *recheckLog) len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.until)
}
