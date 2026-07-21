package session

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
)

func key(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func TestKeyring_SealOpenRoundTrip(t *testing.T) {
	kr := NewKeyring()
	if err := kr.Add("k1", key(1)); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if kr.ActiveID() != "k1" {
		t.Errorf("ActiveID = %q, want k1 (first key added)", kr.ActiveID())
	}
	aad := []byte("session-abc")
	blob, err := kr.Seal([]byte("a-refresh-token"), aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := kr.Open(blob, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(got) != "a-refresh-token" {
		t.Errorf("Open = %q, want the original plaintext", got)
	}
}

func TestKeyring_WrongAADFails(t *testing.T) {
	kr := NewKeyring()
	_ = kr.Add("k1", key(1))
	blob, _ := kr.Seal([]byte("secret"), []byte("session-1"))
	if _, err := kr.Open(blob, []byte("session-2")); err == nil {
		t.Fatal("Open under a different aad must fail (binding to the session id)")
	}
}

func TestKeyring_TamperedCiphertextFails(t *testing.T) {
	kr := NewKeyring()
	_ = kr.Add("k1", key(1))
	blob, _ := kr.Seal([]byte("secret"), []byte("s"))
	blob[len(blob)-1] ^= 0xff // flip a tag bit
	if _, err := kr.Open(blob, []byte("s")); err == nil {
		t.Fatal("Open of tampered ciphertext must fail")
	}
}

func TestKeyring_KeyRotation(t *testing.T) {
	kr := NewKeyring()
	_ = kr.Add("k1", key(1))
	aad := []byte("s")
	oldBlob, _ := kr.Seal([]byte("old"), aad)

	// Roll forward to a new active key.
	if err := kr.Add("k2", key(2)); err != nil {
		t.Fatalf("Add k2: %v", err)
	}
	if err := kr.SetActive("k2"); err != nil {
		t.Fatalf("SetActive: %v", err)
	}
	if kr.ActiveID() != "k2" {
		t.Errorf("ActiveID = %q, want k2", kr.ActiveID())
	}
	newBlob, _ := kr.Seal([]byte("new"), aad)

	// The old blob still decrypts under its original key...
	got, err := kr.Open(oldBlob, aad)
	if err != nil || string(got) != "old" {
		t.Errorf("old blob: got %q, %v; want old, nil", got, err)
	}
	// ...and the new blob decrypts under the new key.
	got, err = kr.Open(newBlob, aad)
	if err != nil || string(got) != "new" {
		t.Errorf("new blob: got %q, %v; want new, nil", got, err)
	}
}

func TestKeyring_UnknownKeyID(t *testing.T) {
	k1 := NewKeyring()
	_ = k1.Add("k1", key(1))
	blob, _ := k1.Seal([]byte("x"), []byte("s"))

	// A ring without k1 cannot open the blob.
	k2 := NewKeyring()
	_ = k2.Add("k2", key(2))
	if _, err := k2.Open(blob, []byte("s")); err == nil {
		t.Fatal("Open with an unknown key id must fail")
	}
}

func TestKeyring_SealWithoutActiveKey(t *testing.T) {
	kr := NewKeyring()
	if _, err := kr.Seal([]byte("x"), nil); !errors.Is(err, ErrNoActiveKey) {
		t.Fatalf("err = %v, want ErrNoActiveKey", err)
	}
}

func TestKeyring_AddRejectsBadKey(t *testing.T) {
	kr := NewKeyring()
	if err := kr.Add("k1", bytes.Repeat([]byte{1}, 16)); err == nil {
		t.Error("Add must reject a 16-byte key (AES-256 needs 32)")
	}
	if err := kr.Add("", key(1)); err == nil {
		t.Error("Add must reject an empty key id")
	}
}

// TestNewKeyringFromBase64_FailOpen verifies the constructor never fails
// over a key problem: a good key becomes the persistent "k1", while an
// absent or invalid key degrades to an ephemeral key (still encrypting, just
// not surviving a restart) rather than erroring. ActiveID reflects which
// path was taken.
func TestNewKeyringFromBase64_FailOpen(t *testing.T) {
	good := make([]byte, 32)
	if _, err := rand.Read(good); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name       string
		key        string
		wantActive string
	}{
		{"valid key", base64.StdEncoding.EncodeToString(good), "k1"},
		{"unset", "", "ephemeral"},
		{"not base64", "@@@not-base64@@@", "ephemeral"},
		{"wrong length", base64.StdEncoding.EncodeToString([]byte("too-short")), "ephemeral"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kr, err := NewKeyringFromBase64(tc.key, "TEST_SESSION_ENC_KEY", nil)
			if err != nil {
				t.Fatalf("NewKeyringFromBase64 must not error on a key problem, got: %v", err)
			}
			if kr.ActiveID() != tc.wantActive {
				t.Errorf("active key id = %q, want %q", kr.ActiveID(), tc.wantActive)
			}
			blob, err := kr.Seal([]byte("token"), []byte("sid"))
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			got, err := kr.Open(blob, []byte("sid"))
			if err != nil || string(got) != "token" {
				t.Errorf("round trip: got %q, %v", got, err)
			}
		})
	}
}

// TestNewKeyringFromBase64_LogsWithEnvVarName verifies the warning message
// names the caller's config source, not a hardcoded one -- the whole point
// of taking envVarName as a parameter.
func TestNewKeyringFromBase64_LogsWithEnvVarName(t *testing.T) {
	var got string
	logf := func(format string, args ...any) { got = fmt.Sprintf(format, args...) }
	if _, err := NewKeyringFromBase64("", "MYAPP_SESSION_ENC_KEY", logf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains([]byte(got), []byte("MYAPP_SESSION_ENC_KEY")) {
		t.Errorf("warning = %q, want it to name MYAPP_SESSION_ENC_KEY", got)
	}
}

func TestKeyring_OpenMalformed(t *testing.T) {
	kr := NewKeyring()
	_ = kr.Add("k1", key(1))
	for _, blob := range [][]byte{nil, {}, {5, 1, 2}} { // empty, and idLen past the end
		if _, err := kr.Open(blob, nil); !errors.Is(err, ErrMalformedCiphertext) {
			t.Errorf("Open(%v) err = %v, want ErrMalformedCiphertext", blob, err)
		}
	}
}
