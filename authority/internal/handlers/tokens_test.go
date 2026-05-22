package handlers

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dslabs/darkroute/authority/internal/auth"
	"github.com/dslabs/darkroute/authority/internal/blind"
)

const testJWTSecret = "test-secret-of-sufficient-length-please-32+"

func testSignerForHandler(t *testing.T) *blind.Signer {
	t.Helper()
	// Reuse LoadOrGenerate against a temp file so we don't duplicate
	// key-construction logic; key generation is ~1s and acceptable here.
	dir := t.TempDir()
	s, err := blind.LoadOrGenerate(dir + "/key.pem")
	if err != nil {
		t.Fatalf("blind signer: %v", err)
	}
	return s
}

func TestPubkeyHandlerReturnsValidPEM(t *testing.T) {
	signer := testSignerForHandler(t)
	h := NewTokenHandler(nil, signer)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/authority/pubkey", nil)
	rec := httptest.NewRecorder()
	h.HandlePubkey(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/x-pem-file" {
		t.Errorf("Content-Type = %q", ct)
	}
	body := rec.Body.Bytes()
	block, _ := pem.Decode(body)
	if block == nil || block.Type != "PUBLIC KEY" {
		t.Fatalf("response is not a PUBLIC KEY PEM block")
	}
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	pub, ok := pubAny.(*rsa.PublicKey)
	if !ok {
		t.Fatal("not RSA")
	}
	if pub.N.BitLen() != 2048 {
		t.Errorf("modulus bits = %d", pub.N.BitLen())
	}
}

// TestIssueRejectsExpiredJWT exercises the Authenticate middleware path that
// guards /api/v1/tokens/issue. An expired token must produce 401, and the
// handler must never run (pool is nil so a handler call would panic).
func TestIssueRejectsExpiredJWT(t *testing.T) {
	jm := auth.NewJWTManager(testJWTSecret)
	signer := testSignerForHandler(t)
	th := NewTokenHandler(nil, signer)

	expired := mintExpiredJWT(t)

	r := chi.NewRouter()
	r.Use(Authenticate(jm, nil))
	r.Post("/api/v1/tokens/issue", th.HandleIssue)

	srv := httptest.NewServer(r)
	defer srv.Close()

	body, _ := json.Marshal(map[string]string{"blinded": "00"})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/tokens/issue", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+expired)
	req.AddCookie(&http.Cookie{Name: "session_id", Value: "irrelevant"})

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

// mintExpiredJWT crafts an HS256 JWT signed with testJWTSecret whose iat/exp
// are firmly in the past. The middleware must reject it as expired.
func mintExpiredJWT(t *testing.T) string {
	t.Helper()
	past := time.Now().Add(-2 * time.Hour)
	claims := auth.Claims{
		Sub:  "subscriber-1",
		Role: "operator",
		Tier: "free",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "subscriber-1",
			IssuedAt:  jwt.NewNumericDate(past.Add(-time.Hour)),
			ExpiresAt: jwt.NewNumericDate(past),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(testJWTSecret))
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// TestIssueIncrementsTokensIssued requires a real DB (TEST_DATABASE_URL).
// It seeds a subscriber + active subscription, calls HandleIssue with a
// valid blinded value, and verifies the counter advanced by exactly one.
func TestIssueIncrementsTokensIssued(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed issue test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	var subID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO subscribers (email, password) VALUES ($1, $2) RETURNING id`,
		"issue-test-"+time.Now().Format("150405.000000")+"@example.test", "x").Scan(&subID); err != nil {
		t.Fatalf("seed subscriber: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM subscribers WHERE id = $1`, subID) })
	if _, err := pool.Exec(ctx,
		`INSERT INTO subscriptions (subscriber_id, tier, status, current_period_start, current_period_end)
		 VALUES ($1, 'free', 'active', NOW(), NOW() + INTERVAL '30 days')`, subID); err != nil {
		t.Fatalf("seed subscription: %v", err)
	}

	signer := testSignerForHandler(t)
	th := NewTokenHandler(pool, signer)

	// Build a valid blinded value: pick m = 2, r = 3 (both coprime to n);
	// b = m * r^e mod n.
	pub := signer.PublicKey()
	m := big.NewInt(2)
	r := big.NewInt(3)
	e := big.NewInt(int64(pub.E))
	rE := new(big.Int).Exp(r, e, pub.N)
	b := new(big.Int).Mul(m, rE)
	b.Mod(b, pub.N)
	body, _ := json.Marshal(map[string]string{"blinded": hex.EncodeToString(b.Bytes())})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tokens/issue", bytes.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), subscriberKey, subID))
	rec := httptest.NewRecorder()
	th.HandleIssue(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, body=%s", rec.Code, rec.Body.String())
	}
	var got struct{ Signed string }
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Signed == "" {
		t.Error("empty signed value")
	}

	var count int64
	if err := pool.QueryRow(ctx,
		`SELECT tokens_issued FROM subscriptions WHERE subscriber_id = $1`, subID,
	).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("tokens_issued = %d, want 1", count)
	}

	// And it must actually be a valid blind signature: sBlind^e mod n == b.
	sBlind, err := hex.DecodeString(got.Signed)
	if err != nil {
		t.Fatal(err)
	}
	sInt := new(big.Int).SetBytes(sBlind)
	check := new(big.Int).Exp(sInt, e, pub.N)
	if check.Cmp(b) != 0 {
		t.Error("returned signature does not verify against b")
	}
}

