// Package blind implements the authority's side of the Chaum blind RSA
// signature protocol used for issuing unlinkable circuit access tokens.
//
// SECURITY_MODEL.md §5 governs this code. The two invariants that must NEVER
// be violated are:
//
//  1. The RSA private key never appears in any log, response body, error
//     message, panic, or external store. Only the raw bytes on disk at
//     RSA_KEY_PATH and the in-memory rsa.PrivateKey value exist.
//  2. The blinded message b and the resulting blind signature s are never
//     persisted. Only the per-subscriber issuance counter is updated.
//
// Sign() performs the raw RSA primitive s = b^d mod n. It deliberately does
// not use crypto/rsa's higher-level signing functions because those apply
// PKCS#1 v1.5 or PSS padding, which is incompatible with the Chaum blind
// signature scheme.
package blind

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
)

// Required modulus size in bits per SECURITY_MODEL §4.
const RSAKeySize = 2048

var (
	ErrInvalidBlindedValue = errors.New("blinded value is out of range [1, n-1]")
)

type Signer struct {
	key    *rsa.PrivateKey
	pemPub []byte
}

// Persists generated keys with 0600 file mode so the private key is never
// world-readable on disk.
func LoadOrGenerate(path string) (*Signer, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		return parsePrivateKey(data)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read rsa key: %w", err)
	}
	return generateAndPersist(path)
}

func parsePrivateKey(data []byte) (*Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block in RSA key file")
	}
	var priv *rsa.PrivateKey
	var perr error
	switch block.Type {
	case "RSA PRIVATE KEY":
		priv, perr = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		anyKey, e2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if e2 != nil {
			return nil, fmt.Errorf("parse pkcs8: %w", e2)
		}
		var ok bool
		priv, ok = anyKey.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("key in file is not RSA")
		}
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
	}
	if perr != nil {
		return nil, fmt.Errorf("parse rsa key: %w", perr)
	}
	if priv.N.BitLen() != RSAKeySize {
		return nil, fmt.Errorf("RSA key must be %d bits, got %d", RSAKeySize, priv.N.BitLen())
	}
	return newSigner(priv)
}

func generateAndPersist(path string) (*Signer, error) {
	priv, err := rsa.GenerateKey(rand.Reader, RSAKeySize)
	if err != nil {
		return nil, fmt.Errorf("generate rsa key: %w", err)
	}
	der := x509.MarshalPKCS1PrivateKey(priv)
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}

	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}
	// O_EXCL prevents racing two startups; a stale key file should be
	// removed manually rather than silently overwritten.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create rsa key file: %w", err)
	}
	if err := pem.Encode(f, block); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("encode rsa pem: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("close rsa key file: %w", err)
	}
	return newSigner(priv)
}

func newSigner(priv *rsa.PrivateKey) (*Signer, error) {
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal pkix pubkey: %w", err)
	}
	pemPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	return &Signer{key: priv, pemPub: pemPub}, nil
}

// Returns a fresh copy so callers can mutate or transmit it without racing
// the shared signer state.
func (s *Signer) PublicKeyPEM() []byte {
	out := make([]byte, len(s.pemPub))
	copy(out, s.pemPub)
	return out
}

func (s *Signer) ModulusSize() int {
	return (s.key.N.BitLen() + 7) / 8
}

func (s *Signer) Sign(blinded []byte) ([]byte, error) {
	if len(blinded) == 0 {
		return nil, ErrInvalidBlindedValue
	}
	b := new(big.Int).SetBytes(blinded)
	if b.Sign() <= 0 || b.Cmp(s.key.N) >= 0 {
		return nil, ErrInvalidBlindedValue
	}
	sig := new(big.Int).Exp(b, s.key.D, s.key.N)
	out := make([]byte, s.ModulusSize())
	sig.FillBytes(out)
	return out, nil
}

// Returns a pointer to the live key; callers must not mutate it.
func (s *Signer) PublicKey() *rsa.PublicKey {
	return &s.key.PublicKey
}
