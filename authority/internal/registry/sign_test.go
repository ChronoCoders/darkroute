package registry

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// repoTestdata locates the shared vector directory from this package.
func repoTestdata(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join("..", "..", "..", "testdata", name)
}

func newSigner(t *testing.T) *Signer {
	t.Helper()
	path := filepath.Join(t.TempDir(), "registry.key")
	if _, err := GenerateKeyFile(path); err != nil {
		t.Fatalf("GenerateKeyFile: %v", err)
	}
	s, err := LoadSigner(path)
	if err != nil {
		t.Fatalf("LoadSigner: %v", err)
	}
	return s
}

func TestSignVerifyRoundTrip(t *testing.T) {
	s := newSigner(t)
	doc := []byte(`{"version":1}`)
	sig := s.Sign(doc)
	if sig.KeyID != s.KeyID() {
		t.Errorf("signature key id %q, want %q", sig.KeyID, s.KeyID())
	}
	raw, err := base64.StdEncoding.DecodeString(sig.Sig)
	if err != nil {
		t.Fatalf("signature is not base64: %v", err)
	}
	if len(raw) != ed25519.SignatureSize {
		t.Fatalf("signature length %d, want %d", len(raw), ed25519.SignatureSize)
	}
	if !Verify(s.PublicKey(), doc, raw) {
		t.Error("a freshly made signature did not verify")
	}
}

// Domain separation: a signature over the bare document must not verify as a
// registry signature, otherwise one could be replayed from any other context
// that signs raw bytes with the same key.
func TestDomainSeparationRejectsBareDocumentSignature(t *testing.T) {
	s := newSigner(t)
	doc := []byte(`{"version":7}`)

	// Control: the domain-separated signature verifies.
	proper, err := base64.StdEncoding.DecodeString(s.Sign(doc).Sig)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !Verify(s.PublicKey(), doc, proper) {
		t.Fatal("control: the proper signature must verify")
	}

	// A signature over the bare bytes, made with the same key, must not.
	bare := ed25519.Sign(s.priv, doc)
	if Verify(s.PublicKey(), doc, bare) {
		t.Error("a signature over the bare document verified as a registry signature")
	}
}

func TestVerifyRejectsAFlippedByte(t *testing.T) {
	s := newSigner(t)
	doc := []byte(`{"version":1,"relays":[]}`)
	sig, err := base64.StdEncoding.DecodeString(s.Sign(doc).Sig)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Control: unmodified verifies.
	if !Verify(s.PublicKey(), doc, sig) {
		t.Fatal("control: the unmodified document must verify")
	}
	for i := range doc {
		flipped := make([]byte, len(doc))
		copy(flipped, doc)
		flipped[i] ^= 0x01
		if Verify(s.PublicKey(), flipped, sig) {
			t.Fatalf("a document with byte %d flipped still verified", i)
		}
	}
}

func TestVerifyRejectsANonPinnedKey(t *testing.T) {
	signerA := newSigner(t)
	signerB := newSigner(t)
	doc := []byte(`{"version":2}`)
	sig, err := base64.StdEncoding.DecodeString(signerA.Sign(doc).Sig)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Control: A's key verifies A's signature.
	if !Verify(signerA.PublicKey(), doc, sig) {
		t.Fatal("control: the signing key must verify its own signature")
	}
	if Verify(signerB.PublicKey(), doc, sig) {
		t.Error("a signature verified under a key that did not make it")
	}
}

// The committed vector, which the Rust client verifies from the same file. This
// is the Go half of the cross-language check.
func TestCommittedRegistryVectorVerifies(t *testing.T) {
	raw, err := os.ReadFile(repoTestdata(t, "registry_vector.json"))
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var v struct {
		Domain       string `json:"domain"`
		PublicKey    string `json:"public_key"`
		KeyID        string `json:"key_id"`
		DocumentB64  string `json:"document_b64"`
		SignatureB64 string `json:"signature_b64"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	if v.Domain != Domain {
		t.Fatalf("vector domain %q, want %q", v.Domain, Domain)
	}
	pub, err := hex.DecodeString(v.PublicKey)
	if err != nil {
		t.Fatalf("public key hex: %v", err)
	}
	doc, err := base64.StdEncoding.DecodeString(v.DocumentB64)
	if err != nil {
		t.Fatalf("document base64: %v", err)
	}
	sig, err := base64.StdEncoding.DecodeString(v.SignatureB64)
	if err != nil {
		t.Fatalf("signature base64: %v", err)
	}
	if !Verify(ed25519.PublicKey(pub), doc, sig) {
		t.Error("the committed registry vector did not verify")
	}
	if got := KeyIDFor(ed25519.PublicKey(pub)); got != v.KeyID {
		t.Errorf("vector key_id %q, derived %q", v.KeyID, got)
	}
	// Control: the same signature must not verify over a changed document.
	doc[0] ^= 0x01
	if Verify(ed25519.PublicKey(pub), doc, sig) {
		t.Error("the vector signature verified over a modified document")
	}
}

// RFC 8032 section 7.1 vectors, public key, message and signature only. These
// check the primitive itself rather than our wrapper, so they are verified with
// plain ed25519.Verify and not through Verify, which adds domain separation.
func TestRFC8032Vectors(t *testing.T) {
	raw, err := os.ReadFile(repoTestdata(t, "ed25519_rfc8032.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var doc struct {
		Vectors []struct {
			Name      string `json:"name"`
			PublicKey string `json:"public_key"`
			Message   string `json:"message"`
			Signature string `json:"signature"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(doc.Vectors) == 0 {
		t.Fatal("no vectors loaded, so this test would pass vacuously")
	}
	for _, v := range doc.Vectors {
		pub, err := hex.DecodeString(v.PublicKey)
		if err != nil {
			t.Fatalf("%s: public key hex: %v", v.Name, err)
		}
		msg, err := hex.DecodeString(v.Message)
		if err != nil {
			t.Fatalf("%s: message hex: %v", v.Name, err)
		}
		sig, err := hex.DecodeString(v.Signature)
		if err != nil {
			t.Fatalf("%s: signature hex: %v", v.Name, err)
		}
		if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
			t.Errorf("%s did not verify", v.Name)
		}
		// Control: a flipped signature byte must fail, so a broken verifier
		// that accepts everything cannot pass this test.
		bad := make([]byte, len(sig))
		copy(bad, sig)
		bad[0] ^= 0x01
		if ed25519.Verify(ed25519.PublicKey(pub), msg, bad) {
			t.Errorf("%s verified with a corrupted signature", v.Name)
		}
	}
}
