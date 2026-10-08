package registry

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
)

// Domain is the signature label. The 0x00 byte after it makes the prefix
// unambiguous, so bytes signed under this label can never be read as bytes
// signed under a longer label that happens to start with it.
const Domain = "quiethop/v1/registry"

// signedMessage returns Domain || 0x00 || document.
//
// Signing the bare document would let a signature be replayed into any other
// context that signs raw bytes with the same key.
func signedMessage(document []byte) []byte {
	msg := make([]byte, 0, len(Domain)+1+len(document))
	msg = append(msg, Domain...)
	msg = append(msg, 0x00)
	msg = append(msg, document...)
	return msg
}

// Signature is one entry in the detached signature list. More than one may
// appear once operators co-sign, which is why this is a list and not a field.
type Signature struct {
	KeyID string `json:"key_id"`
	Sig   string `json:"sig"`
}

// Sign returns the detached signature over the domain-separated document.
func (s *Signer) Sign(document []byte) Signature {
	sig := ed25519.Sign(s.priv, signedMessage(document))
	return Signature{KeyID: s.keyID, Sig: b64(sig)}
}

// Verify checks a signature against a public key. The authority uses this only
// in tests and when reading back a stored row; clients verify in Rust.
func Verify(pub ed25519.PublicKey, document []byte, sig []byte) bool {
	return ed25519.Verify(pub, signedMessage(document), sig)
}

// Response is the exact wire shape of GET /api/v1/registry.
//
// The document travels base64-encoded so the signed bytes survive any proxy or
// re-serialisation on the way to the client. A client decodes, verifies, and
// only then parses: nothing inside the document is trusted before the
// signature checks out.
type Response struct {
	Document   string      `json:"document"`
	Signatures []Signature `json:"signatures"`
}

// MarshalSignatures renders the signature list for storage, in the same shape
// it is served, so a stored row can be re-served without rebuilding it.
func MarshalSignatures(sigs []Signature) ([]byte, error) {
	return json.Marshal(sigs)
}

// UnmarshalSignatures reads a stored signature list back.
func UnmarshalSignatures(raw []byte) ([]Signature, error) {
	var out []Signature
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func b64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
