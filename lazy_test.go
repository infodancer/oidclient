package oidclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// downProvider is an issuer URL whose server always responds 503, simulating
// an unreachable or broken IdP.
func downProvider(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestNewLazy_RequiresIssuer(t *testing.T) {
	if _, err := NewLazy(context.Background(), Config{}); err == nil {
		t.Fatal("NewLazy without IssuerURL should error")
	}
}

func TestNewLazy_DegradesWhileProviderDown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c, err := newLazy(ctx, Config{
		IssuerURL:   downProvider(t),
		CookieName:  "test_jwt",
		ClientID:    "test-client",
		CallbackURL: "https://app.example/auth/callback",
	}, 10*time.Millisecond, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("newLazy: %v", err)
	}

	if c.Ready() {
		t.Error("Ready() = true with the provider down")
	}
	if _, err := c.Validate(ctx, "some-token"); !errors.Is(err, ErrNotReady) {
		t.Errorf("Validate err = %v, want ErrNotReady", err)
	}
	if _, _, err := c.ExchangeCode(ctx, "code", "verifier"); !errors.Is(err, ErrNotReady) {
		t.Errorf("ExchangeCode err = %v, want ErrNotReady", err)
	}
	if got := c.AuthorizeURL("state", "verifier"); got != "" {
		t.Errorf("AuthorizeURL = %q, want empty while not ready", got)
	}
	// Config-only surfaces keep working so pages can still render chrome.
	if c.CookieName() != "test_jwt" {
		t.Errorf("CookieName = %q", c.CookieName())
	}
	if c.ClientID() != "test-client" {
		t.Errorf("ClientID = %q", c.ClientID())
	}

	// The callback endpoint degrades to 503 instead of crashing or 502ing.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=x&state=y", nil)
	c.CallbackHandler(CallbackOptions{}).ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("callback status = %d, want 503", rr.Code)
	}
}

func TestNewLazy_RecoversWhenProviderComesUp(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mux, setBase, issueToken := fakeProviderMux(t)
	var up atomic.Bool
	gate := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		mux.ServeHTTP(w, r)
	})
	srv := httptest.NewServer(gate)
	t.Cleanup(srv.Close)
	setBase(srv.URL)

	c, err := newLazy(ctx, Config{
		IssuerURL:  srv.URL,
		CookieName: "test_jwt",
		ClientID:   "test-client",
	}, 5*time.Millisecond, 20*time.Millisecond)
	if err != nil {
		t.Fatalf("newLazy: %v", err)
	}
	if c.Ready() {
		t.Fatal("Ready() = true before the provider is up")
	}

	up.Store(true)

	deadline := time.Now().Add(5 * time.Second)
	for !c.Ready() {
		if time.Now().After(deadline) {
			t.Fatal("client never became ready after the provider came up")
		}
		time.Sleep(5 * time.Millisecond)
	}

	tok := issueToken("sub-1", "u@example.com", time.Hour)
	claims, err := c.Validate(ctx, tok)
	if err != nil {
		t.Fatalf("Validate after recovery: %v", err)
	}
	if claims.Sub != "sub-1" {
		t.Errorf("sub = %q", claims.Sub)
	}
	if got := c.AuthorizeURL("state", "verifier"); got == "" {
		t.Error("AuthorizeURL empty after recovery")
	}
}

func TestNewLazy_StopsRetryingOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	issuer := downProvider(t)

	c, err := newLazy(ctx, Config{IssuerURL: issuer, ClientID: "x"}, time.Millisecond, time.Millisecond)
	if err != nil {
		t.Fatalf("newLazy: %v", err)
	}
	cancel()
	// Give the goroutine a moment to observe cancellation; it must not flip
	// to ready afterwards even if the provider recovers.
	time.Sleep(20 * time.Millisecond)
	if c.Ready() {
		t.Error("Ready() = true after context cancellation")
	}
}

func TestNew_StaysEager(t *testing.T) {
	if _, err := New(context.Background(), Config{IssuerURL: downProvider(t), ClientID: "x"}); err == nil {
		t.Fatal("New against a down provider should fail eagerly")
	}
}
