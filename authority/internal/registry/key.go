// Package registry builds, signs and serves the signed relay registry.
package registry

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// KeyFileLen is the on-disk length: the 32-byte Ed25519 seed only.
//
// Go's ed25519.PrivateKey is 64 bytes (seed followed by public key), but the
// public half is derivable from the seed, so storing it would add a second copy
// that could disagree with the first. The seed is the whole secret.
const KeyFileLen = ed25519.SeedSize

// requiredMode is the only acceptable file mode. Anything with a bit outside
// this is too loose (SECURITY_MODEL 8).
const requiredMode fs.FileMode = 0o600

// KeyIDLen is the length of a key id: the first 8 bytes of SHA-256 over the raw
// 32-byte public key, matching the epoch key id convention in
// SECURITY_MODEL 5.2. A raw Ed25519 public key has one representation, so there
// is no DER encoding to hash.
const KeyIDLen = 8

var (
	ErrKeyMissing    = errors.New("registry signing key file does not exist")
	ErrKeyMode       = errors.New("registry signing key file mode is looser than 0600")
	ErrKeyLength     = errors.New("registry signing key file is not the expected length")
	ErrKeyExists     = errors.New("registry signing key file already exists")
	ErrKeyUnreadable = errors.New("registry signing key file is not readable")
)

// Signer holds the registry signing key. The seed never leaves this struct and
// is never logged, printed or returned.
type Signer struct {
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
	keyID string
}

// KeyID returns the hex key id that appears in every signature entry.
func (s *Signer) KeyID() string { return s.keyID }

// PublicKey returns a copy of the public half. Public material, safe to log.
func (s *Signer) PublicKey() ed25519.PublicKey {
	out := make(ed25519.PublicKey, len(s.pub))
	copy(out, s.pub)
	return out
}

// KeyIDFor derives the key id for a public key.
func KeyIDFor(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:KeyIDLen])
}

// LoadSigner reads the key and refuses anything missing, unreadable, too
// loosely permissioned or the wrong length.
//
// It never generates. A registry key invented at startup would sign a document
// no client has pinned, so every client would reject every registry and the
// cause would be invisible from the authority's side (ARCHITECTURE 4.4).
func LoadSigner(path string) (*Signer, error) {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrKeyMissing, path)
		}
		return nil, fmt.Errorf("%w: %s: %v", ErrKeyUnreadable, path, err)
	}
	if mode := info.Mode().Perm(); mode&^requiredMode != 0 {
		return nil, fmt.Errorf("%w: %s has mode %04o", ErrKeyMode, path, mode)
	}

	seed, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrKeyUnreadable, path, err)
	}
	defer zero(seed)
	if len(seed) != KeyFileLen {
		return nil, fmt.Errorf("%w: %s is %d bytes, want %d", ErrKeyLength, path, len(seed), KeyFileLen)
	}

	priv := ed25519.NewKeyFromSeed(seed)
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrKeyUnreadable, path)
	}
	return &Signer{priv: priv, pub: pub, keyID: KeyIDFor(pub)}, nil
}

// GenerateKeyFile writes a new seed with mode 0600 and refuses to overwrite.
//
// Returns the public key hex for the operator to pin into clients. The seed is
// zeroed before returning and is never logged or printed.
func GenerateKeyFile(path string) (string, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return "", fmt.Errorf("generate registry key: %w", err)
	}
	seed := priv.Seed()
	defer zero(seed)

	// O_EXCL makes the create exclusive, so two concurrent runs cannot both
	// believe they wrote the file.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, requiredMode)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf("%w: %s", ErrKeyExists, path)
		}
		return "", fmt.Errorf("create %s: %w", path, err)
	}
	if _, err := f.Write(seed); err != nil {
		f.Close()
		return "", fmt.Errorf("write %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("close %s: %w", path, err)
	}
	return hex.EncodeToString(pub), nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
