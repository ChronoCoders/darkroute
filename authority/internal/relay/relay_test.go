package relay

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestValidRole(t *testing.T) {
	for _, r := range []string{"guard", "middle", "exit"} {
		if !validRole(r) {
			t.Errorf("validRole(%q) = false", r)
		}
	}
	for _, r := range []string{"", "GUARD", "admin", "client"} {
		if validRole(r) {
			t.Errorf("validRole(%q) = true (should be false)", r)
		}
	}
}

func TestHashAPIKeyIsDeterministic(t *testing.T) {
	a := hashAPIKey("salt", "key")
	b := hashAPIKey("salt", "key")
	if a != b {
		t.Errorf("expected hash to be deterministic")
	}
	if hashAPIKey("salt", "key") == hashAPIKey("different-salt", "key") {
		t.Errorf("salt must affect hash")
	}
	if hashAPIKey("salt", "key1") == hashAPIKey("salt", "key2") {
		t.Errorf("plaintext must affect hash")
	}
	if len(hashAPIKey("salt", "key")) != 64 {
		t.Errorf("hash length: got %d want 64", len(hashAPIKey("salt", "key")))
	}
}

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed relay test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping: %v", err)
	}
	return pool
}

func TestProvisionAndSweep(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	ctx := context.Background()

	id, plaintext, err := ProvisionRelay(ctx, pool, "test-salt-1234567890", "10.0.0.50:9001", "us-east", "guard")
	if err != nil {
		t.Fatalf("ProvisionRelay: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM relay_nodes WHERE id = $1`, id)
	})
	if !strings.ContainsAny(plaintext, "0123456789abcdef") || len(plaintext) != 64 {
		t.Errorf("plaintext key not 64-char hex: %q", plaintext)
	}

	gotID, err := RecordHeartbeat(ctx, pool, "test-salt-1234567890", plaintext)
	if err != nil {
		t.Fatalf("RecordHeartbeat: %v", err)
	}
	if gotID != id {
		t.Errorf("heartbeat returned id %q want %q", gotID, id)
	}

	if _, err := RecordHeartbeat(ctx, pool, "test-salt-1234567890", "wrong-key"); err == nil {
		t.Errorf("expected unknown relay error for bad key")
	}

	n, err := SweepInactiveRelays(ctx, pool, time.Nanosecond)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if n < 1 {
		t.Errorf("expected at least 1 relay swept inactive, got %d", n)
	}

	n2, err := SweepInactiveRelays(ctx, pool, time.Nanosecond)
	if err != nil {
		t.Fatalf("Sweep 2: %v", err)
	}
	if n2 != 0 {
		t.Errorf("second sweep should mark 0 rows, got %d", n2)
	}
}

// Per SECURITY_MODEL §9: this exclusion mechanism is how the circuit-route
// handler guarantees three distinct physical hops.
func TestPickRandomActiveByRoleExcludesIDs(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	ctx := context.Background()

	seedActiveGuard := func() string {
		var id string
		if err := pool.QueryRow(ctx,
			`INSERT INTO relay_nodes (id, api_key_hash, endpoint, region, role, status, last_heartbeat)
			 VALUES (gen_random_uuid(), $1, $2, 'us-east', 'guard', 'active', NOW())
			 RETURNING id`,
			"test-hash-exclude-"+time.Now().Format("150405.000000")+"-"+strings.Repeat("x", 4),
			"10.0.0.99:9001",
		).Scan(&id); err != nil {
			t.Fatalf("seed guard: %v", err)
		}
		t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM relay_nodes WHERE id = $1`, id) })
		return id
	}

	g1 := seedActiveGuard()
	g2 := seedActiveGuard()

	r, err := PickRandomActiveByRole(ctx, pool, "guard")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ID != g1 && r.ID != g2 {
		t.Fatalf("returned id %q is neither seeded guard", r.ID)
	}

	r, err = PickRandomActiveByRole(ctx, pool, "guard", g1)
	if err != nil {
		t.Fatalf("unexpected error excluding g1: %v", err)
	}
	if r.ID != g2 {
		t.Errorf("excluding g1 returned %q, expected g2 (%q)", r.ID, g2)
	}

	if _, err := PickRandomActiveByRole(ctx, pool, "guard", g1, g2); err == nil {
		t.Errorf("expected error when both guards excluded, got nil")
	}
}

func TestProvisionRejectsInvalidRole(t *testing.T) {
	// No DB needed — the role check happens before any query.
	_, _, err := ProvisionRelay(context.Background(), nil, "salt", "endpoint", "region", "admin")
	if err != ErrInvalidRole {
		t.Errorf("expected ErrInvalidRole, got %v", err)
	}
}
