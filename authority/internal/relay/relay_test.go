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
		if !ValidRole(r) {
			t.Errorf("ValidRole(%q) = false", r)
		}
	}
	for _, r := range []string{"", "GUARD", "admin", "client"} {
		if ValidRole(r) {
			t.Errorf("ValidRole(%q) = true (should be false)", r)
		}
	}
}

func TestHashAPIKeyIsDeterministic(t *testing.T) {
	a := HashAPIKey("salt", "key")
	b := HashAPIKey("salt", "key")
	if a != b {
		t.Errorf("expected hash to be deterministic")
	}
	if HashAPIKey("salt", "key") == HashAPIKey("different-salt", "key") {
		t.Errorf("salt must affect hash")
	}
	if HashAPIKey("salt", "key1") == HashAPIKey("salt", "key2") {
		t.Errorf("plaintext must affect hash")
	}
	// hex-encoded SHA-256 is 64 chars
	if len(HashAPIKey("salt", "key")) != 64 {
		t.Errorf("hash length: got %d want 64", len(HashAPIKey("salt", "key")))
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

	// Sweep with a TTL of 1 nanosecond should mark this active relay inactive.
	n, err := SweepInactiveRelays(ctx, pool, time.Nanosecond)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if n < 1 {
		t.Errorf("expected at least 1 relay swept inactive, got %d", n)
	}

	// A second sweep should affect 0 rows (already inactive).
	n2, err := SweepInactiveRelays(ctx, pool, time.Nanosecond)
	if err != nil {
		t.Fatalf("Sweep 2: %v", err)
	}
	if n2 != 0 {
		t.Errorf("second sweep should mark 0 rows, got %d", n2)
	}
}

func TestProvisionRejectsInvalidRole(t *testing.T) {
	// No DB needed — the role check happens before any query.
	_, _, err := ProvisionRelay(context.Background(), nil, "salt", "endpoint", "region", "admin")
	if err != ErrInvalidRole {
		t.Errorf("expected ErrInvalidRole, got %v", err)
	}
}
