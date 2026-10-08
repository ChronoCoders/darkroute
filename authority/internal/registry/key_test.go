package registry

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// Every key in this package's tests is generated at run time into t.TempDir().
// No key material is committed, and no seed is ever printed.

func TestGenerateThenLoadRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.key")
	pubHex, err := GenerateKeyFile(path)
	if err != nil {
		t.Fatalf("GenerateKeyFile: %v", err)
	}
	if len(pubHex) != ed25519.PublicKeySize*2 {
		t.Fatalf("public hex length %d, want %d", len(pubHex), ed25519.PublicKeySize*2)
	}

	s, err := LoadSigner(path)
	if err != nil {
		t.Fatalf("LoadSigner: %v", err)
	}
	if got := hex.EncodeToString(s.PublicKey()); got != pubHex {
		t.Errorf("loaded public key %s, want %s", got, pubHex)
	}
	if want := KeyIDFor(s.PublicKey()); s.KeyID() != want {
		t.Errorf("key id %s, want %s", s.KeyID(), want)
	}
}

func TestGeneratedFileIsMode0600AndSeedLength(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.key")
	if _, err := GenerateKeyFile(path); err != nil {
		t.Fatalf("GenerateKeyFile: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("mode %04o, want 0600", got)
	}
	if got := info.Size(); got != int64(KeyFileLen) {
		t.Errorf("size %d, want %d", got, KeyFileLen)
	}
}

func TestGenerateRefusesToOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.key")
	first, err := GenerateKeyFile(path)
	if err != nil {
		t.Fatalf("first GenerateKeyFile: %v", err)
	}
	if _, err := GenerateKeyFile(path); !isErr(err, ErrKeyExists) {
		t.Fatalf("second GenerateKeyFile: err = %v, want ErrKeyExists", err)
	}
	// The original is untouched.
	s, err := LoadSigner(path)
	if err != nil {
		t.Fatalf("LoadSigner after refused overwrite: %v", err)
	}
	if got := hex.EncodeToString(s.PublicKey()); got != first {
		t.Error("a refused overwrite changed the key on disk")
	}
}

func TestLoadRejectsMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.key")
	if _, err := LoadSigner(path); !isErr(err, ErrKeyMissing) {
		t.Errorf("err = %v, want ErrKeyMissing", err)
	}
}

func TestLoadRejectsModeLooserThan0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.key")
	if _, err := GenerateKeyFile(path); err != nil {
		t.Fatalf("GenerateKeyFile: %v", err)
	}
	// Control: it loads at 0600.
	if _, err := LoadSigner(path); err != nil {
		t.Fatalf("control load at 0600 failed: %v", err)
	}
	for _, mode := range []os.FileMode{0o640, 0o604, 0o660, 0o644, 0o700} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatalf("chmod %04o: %v", mode, err)
		}
		if _, err := LoadSigner(path); !isErr(err, ErrKeyMode) {
			t.Errorf("mode %04o: err = %v, want ErrKeyMode", mode, err)
		}
	}
}

func TestLoadAcceptsStricterMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.key")
	if _, err := GenerateKeyFile(path); err != nil {
		t.Fatalf("GenerateKeyFile: %v", err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if _, err := LoadSigner(path); err != nil {
		t.Errorf("0400 is stricter than 0600 and must load: %v", err)
	}
}

func TestLoadRejectsWrongLength(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []int{KeyFileLen - 1, KeyFileLen + 1, 0} {
		path := filepath.Join(dir, "k"+string(rune('a'+n%26))+".key")
		if err := os.WriteFile(path, make([]byte, n), 0o600); err != nil {
			t.Fatalf("write %d bytes: %v", n, err)
		}
		if _, err := LoadSigner(path); !isErr(err, ErrKeyLength) {
			t.Errorf("length %d: err = %v, want ErrKeyLength", n, err)
		}
	}
}

func TestTwoGeneratesProduceDifferentKeys(t *testing.T) {
	dir := t.TempDir()
	a, err := GenerateKeyFile(filepath.Join(dir, "a.key"))
	if err != nil {
		t.Fatalf("a: %v", err)
	}
	b, err := GenerateKeyFile(filepath.Join(dir, "b.key"))
	if err != nil {
		t.Fatalf("b: %v", err)
	}
	if a == b {
		t.Error("keygen must not be deterministic")
	}
}

func TestKeyIDIsFirstEightBytesOfSHA256(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.key")
	if _, err := GenerateKeyFile(path); err != nil {
		t.Fatalf("GenerateKeyFile: %v", err)
	}
	s, err := LoadSigner(path)
	if err != nil {
		t.Fatalf("LoadSigner: %v", err)
	}
	if len(s.KeyID()) != KeyIDLen*2 {
		t.Errorf("key id hex length %d, want %d", len(s.KeyID()), KeyIDLen*2)
	}
}

func isErr(err, target error) bool {
	for err != nil {
		if err == target {
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
