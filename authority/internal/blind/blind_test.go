package blind

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

func testSigner(t *testing.T) *Signer {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, RSAKeySize)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	s, err := newSigner(priv)
	if err != nil {
		t.Fatalf("newSigner: %v", err)
	}
	return s
}

func TestBlindSignRoundTrip(t *testing.T) {
	s := testSigner(t)
	pub := s.PublicKey()

	mRaw := []byte("phase-3-test-message-preimage-32")
	hash := sha256.Sum256(mRaw)
	m := new(big.Int).SetBytes(hash[:])
	if m.Cmp(pub.N) >= 0 {
		t.Fatalf("test invariant: m must be < n")
	}

	r, err := rand.Int(rand.Reader, pub.N)
	if err != nil {
		t.Fatal(err)
	}
	for new(big.Int).GCD(nil, nil, r, pub.N).Cmp(big.NewInt(1)) != 0 || r.Sign() == 0 {
		r, err = rand.Int(rand.Reader, pub.N)
		if err != nil {
			t.Fatal(err)
		}
	}

	e := big.NewInt(int64(pub.E))
	rE := new(big.Int).Exp(r, e, pub.N)
	b := new(big.Int).Mul(m, rE)
	b.Mod(b, pub.N)

	signed, err := s.Sign(b.Bytes())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	sBlind := new(big.Int).SetBytes(signed)

	rInv := new(big.Int).ModInverse(r, pub.N)
	if rInv == nil {
		t.Fatalf("r has no inverse mod n")
	}
	token := new(big.Int).Mul(sBlind, rInv)
	token.Mod(token, pub.N)

	check := new(big.Int).Exp(token, e, pub.N)
	if check.Cmp(m) != 0 {
		t.Fatalf("blind signature verification failed: check != m")
	}
}

func TestSignRejectsOutOfRangeBlinded(t *testing.T) {
	s := testSigner(t)
	if _, err := s.Sign(nil); err != ErrInvalidBlindedValue {
		t.Errorf("nil: got %v, want ErrInvalidBlindedValue", err)
	}
	if _, err := s.Sign([]byte{}); err != ErrInvalidBlindedValue {
		t.Errorf("empty: got %v, want ErrInvalidBlindedValue", err)
	}
	zero := make([]byte, s.ModulusSize())
	if _, err := s.Sign(zero); err != ErrInvalidBlindedValue {
		t.Errorf("zero: got %v, want ErrInvalidBlindedValue", err)
	}
	if _, err := s.Sign(s.key.N.Bytes()); err != ErrInvalidBlindedValue {
		t.Errorf("n: got %v, want ErrInvalidBlindedValue", err)
	}
}

func TestPublicKeyPEMRoundTrip(t *testing.T) {
	s := testSigner(t)
	raw := s.PublicKeyPEM()
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("expected a PEM block")
	}
	if block.Type != "PUBLIC KEY" {
		t.Errorf("PEM type = %q, want PUBLIC KEY", block.Type)
	}
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey: %v", err)
	}
	pub, ok := pubAny.(*rsa.PublicKey)
	if !ok {
		t.Fatal("decoded pubkey is not RSA")
	}
	if pub.N.BitLen() != RSAKeySize {
		t.Errorf("modulus bits = %d, want %d", pub.N.BitLen(), RSAKeySize)
	}
	if pub.N.Cmp(s.PublicKey().N) != 0 {
		t.Error("modulus mismatch between PEM and Signer")
	}
}

func TestPublicKeyPEMIsACopy(t *testing.T) {
	s := testSigner(t)
	a := s.PublicKeyPEM()
	a[0] = a[0] ^ 0xFF
	b := s.PublicKeyPEM()
	if a[0] == b[0] {
		t.Error("PublicKeyPEM returned a shared buffer; callers can mutate state")
	}
}

func TestLoadOrGenerateCreatesFileOnFirstRun(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "authority.pem")

	s1, err := LoadOrGenerate(path)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("file mode = %o, want 0600", mode)
	}

	s2, err := LoadOrGenerate(path)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if s1.PublicKey().N.Cmp(s2.PublicKey().N) != 0 {
		t.Error("LoadOrGenerate did not return the same key on second call")
	}
}
