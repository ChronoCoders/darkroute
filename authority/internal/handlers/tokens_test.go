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
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"

	"github.com/ChronoCoders/darkrouter/authority/internal/auth"
	"github.com/ChronoCoders/darkrouter/authority/internal/blind"
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

// An expired token must produce 401, and the handler must never run
// (pool is nil so a handler call would panic if the middleware lets it
// through).
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

func TestIssueIncrementsTokensIssued(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	var subID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO subscribers (email, password) VALUES ($1, $2) RETURNING id`,
		"issue-test-"+time.Now().Format("150405.000000")+"@example.test", "x").Scan(&subID); err != nil {
		t.Fatalf("seed subscriber: %v", err)
	}
	cleanupRow(t, pool, deleteSubscriberByID, subID)
	if _, err := pool.Exec(ctx,
		`INSERT INTO subscriptions (subscriber_id, tier, status, current_period_start, current_period_end)
		 VALUES ($1, 'free', 'active', NOW(), NOW() + INTERVAL '30 days')`, subID); err != nil {
		t.Fatalf("seed subscription: %v", err)
	}

	signer := testSignerForHandler(t)
	th := NewTokenHandler(pool, signer)

	// m = 2, r = 3 are both coprime to n; b = m * r^e mod n.
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

// SECURITY_MODEL 5.4: issuance requires an active subscription. The onboarding gate
// leaves a new subscriber at pending_review until an admin approves, and nothing
// covered that path, so removing the status check went unnoticed by the whole suite.
// The blinded value is well formed on purpose, so a 403 cannot come from the body.
func TestIssueRejectsPendingReviewSubscription(t *testing.T) {
	pool := testPool(t)
	subID := seedSubscriberWithSubscription(t, pool, "pending", "pending_review")

	signer := testSignerForHandler(t)
	th := NewTokenHandler(pool, signer)

	pub := signer.PublicKey()
	m := big.NewInt(2)
	r := big.NewInt(3)
	e := big.NewInt(int64(pub.E))
	rE := new(big.Int).Exp(r, e, pub.N)
	b := new(big.Int).Mul(m, rE)
	b.Mod(b, pub.N)
	body, err := json.Marshal(map[string]string{"blinded": hex.EncodeToString(b.Bytes())})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tokens/issue", bytes.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), subscriberKey, subID))
	rec := httptest.NewRecorder()
	th.HandleIssue(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("a pending_review subscriber got %d, want 403 (body=%s)", rec.Code, rec.Body.String())
	}
	var issued int64
	if err := pool.QueryRow(context.Background(),
		`SELECT tokens_issued FROM subscriptions WHERE subscriber_id = $1`, subID).Scan(&issued); err != nil {
		t.Fatal(err)
	}
	if issued != 0 {
		t.Errorf("tokens_issued = %d after a refused issuance, want 0", issued)
	}
}
