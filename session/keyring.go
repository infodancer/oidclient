package session

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
)

// ErrNoActiveKey is returned by Seal when the keyring has no active key.
var ErrNoActiveKey = errors.New("oidclient/session: keyring has no active key")

// ErrMalformedCiphertext is returned by Open when a blob is too short or
// otherwise not a value produced by Seal.
var ErrMalformedCiphertext = errors.New("oidclient/session: malformed ciphertext")

// Keyring holds the AES-256-GCM keys used to encrypt token material at rest.
// One key is active and used for new Seals; every key in the ring can Open a
// blob it produced, selected by the key id stamped into the blob. This lets a
// key roll forward: add a new key, SetActive it, and old rows keep decrypting
// under their original key until they are next rotated and re-sealed.
//
// A Keyring is safe for concurrent use.
type Keyring struct {
	mu     sync.RWMutex
	keys   map[string]cipher.AEAD
	active string
}

// NewKeyring returns an empty keyring. Add at least one key before use.
func NewKeyring() *Keyring {
	return &Keyring{keys: make(map[string]cipher.AEAD)}
}

// Add registers a 32-byte (AES-256) key under id. The id is stamped into every
// blob the key seals, so it must be stable for the life of any data encrypted
// under it and short (at most 255 bytes). The first key added becomes active.
func (k *Keyring) Add(id string, key []byte) error {
	if id == "" {
		return errors.New("oidclient/session: empty key id")
	}
	if len(id) > 255 {
		return fmt.Errorf("oidclient/session: key id %q too long (max 255 bytes)", id)
	}
	if len(key) != 32 {
		return fmt.Errorf("oidclient/session: key %q must be 32 bytes for AES-256, got %d", id, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("oidclient/session: new cipher for key %q: %w", id, err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("oidclient/session: new GCM for key %q: %w", id, err)
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.keys[id] = aead
	if k.active == "" {
		k.active = id
	}
	return nil
}

// SetActive selects which registered key seals new blobs.
func (k *Keyring) SetActive(id string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if _, ok := k.keys[id]; !ok {
		return fmt.Errorf("oidclient/session: no key %q in ring", id)
	}
	k.active = id
	return nil
}

// ActiveID returns the id of the active key, or "" if none is set.
func (k *Keyring) ActiveID() string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.active
}

// blob layout: [1-byte idLen][idLen bytes key id][nonce][ciphertext||tag].

// Seal encrypts plaintext under the active key, binding aad (the session id) so
// the result cannot be decrypted in the context of a different row. The
// returned blob carries the key id and nonce; store it as-is.
func (k *Keyring) Seal(plaintext, aad []byte) ([]byte, error) {
	k.mu.RLock()
	id, aead := k.active, k.keys[k.active]
	k.mu.RUnlock()
	if id == "" || aead == nil {
		return nil, ErrNoActiveKey
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("oidclient/session: nonce: %w", err)
	}
	ct := aead.Seal(nil, nonce, plaintext, aad)
	out := make([]byte, 0, 1+len(id)+len(nonce)+len(ct))
	out = append(out, byte(len(id)))
	out = append(out, id...)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// Open decrypts a blob produced by Seal, using the key id stamped into it and
// verifying aad. It returns an error for an unknown key id, a malformed blob, or
// a failed authentication (wrong key, tampered ciphertext, or mismatched aad).
func (k *Keyring) Open(blob, aad []byte) ([]byte, error) {
	if len(blob) < 1 {
		return nil, ErrMalformedCiphertext
	}
	idLen := int(blob[0])
	if len(blob) < 1+idLen {
		return nil, ErrMalformedCiphertext
	}
	id := string(blob[1 : 1+idLen])
	rest := blob[1+idLen:]

	k.mu.RLock()
	aead := k.keys[id]
	k.mu.RUnlock()
	if aead == nil {
		return nil, fmt.Errorf("oidclient/session: unknown key id %q", id)
	}
	ns := aead.NonceSize()
	if len(rest) < ns {
		return nil, ErrMalformedCiphertext
	}
	nonce, ct := rest[:ns], rest[ns:]
	pt, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, fmt.Errorf("oidclient/session: decrypt: %w", err)
	}
	return pt, nil
}
