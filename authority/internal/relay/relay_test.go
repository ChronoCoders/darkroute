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
	// Closing the pool is registered here, before any caller registers a row
	// cleanup, so LIFO runs it last. A deferred Close runs before every t.Cleanup,
	// which silently broke every row delete in this package and let rows build up
	// across runs.
	t.Cleanup(pool.Close)
	return pool
}

// cleanupRow removes one row the test created and fails if it does not go. These
// deletes used to be written as `_, _ =`, which hid both the closed-pool error and
// the leak it caused.
func cleanupRow(t *testing.T, pool *pgxpool.Pool, sql, id string) {
	t.Helper()
	t.Cleanup(func() {
		tag, err := pool.Exec(context.Background(), sql, id)
		if err != nil {
			t.Errorf("cleanup %q id=%s: %v", sql, id, err)
			return
		}
		if tag.RowsAffected() != 1 {
			t.Errorf("cleanup %q id=%s removed %d rows, want 1", sql, id, tag.RowsAffected())
		}
	})
}

const deleteRelayByID = `DELETE FROM relay_nodes WHERE id = $1`

func relayStatus(t *testing.T, pool *pgxpool.Pool, id string) string {
	t.Helper()
	var s string
	if err := pool.QueryRow(context.Background(),
		`SELECT status FROM relay_nodes WHERE id = $1`, id).Scan(&s); err != nil {
		t.Fatalf("read status of %s: %v", id, err)
	}
	return s
}

func TestProvisionAndSweep(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	id, plaintext, err := ProvisionRelay(ctx, pool, "test-salt-1234567890", "10.0.0.50:9001", "us-east", "guard")
	if err != nil {
		t.Fatalf("ProvisionRelay: %v", err)
	}
	cleanupRow(t, pool, deleteRelayByID, id)
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

	if got := relayStatus(t, pool, id); got != "active" {
		t.Fatalf("after heartbeat status = %q, want active", got)
	}

	// The row is aged explicitly rather than by sleeping. SweepInactiveRelays
	// floors its ttl at one second, so a freshly heartbeated row can never be
	// swept however small a ttl is passed. The previous version of this test
	// passed time.Nanosecond, swept nothing, and so asserted nothing.
	if _, err := pool.Exec(ctx,
		`UPDATE relay_nodes SET last_heartbeat = NOW() - interval '1 hour' WHERE id = $1`, id,
	); err != nil {
		t.Fatalf("age the heartbeat: %v", err)
	}

	n, err := SweepInactiveRelays(ctx, pool, 30*time.Second)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	// A lower bound, not an equality: other rows in a shared database may be stale
	// too, and this row alone guarantees at least one.
	if n < 1 {
		t.Errorf("expected at least 1 relay swept inactive, got %d", n)
	}
	if got := relayStatus(t, pool, id); got != "inactive" {
		t.Errorf("after sweep status = %q, want inactive", got)
	}

	if _, err := SweepInactiveRelays(ctx, pool, 30*time.Second); err != nil {
		t.Fatalf("Sweep 2: %v", err)
	}
	if got := relayStatus(t, pool, id); got != "inactive" {
		t.Errorf("after second sweep status = %q, want inactive", got)
	}
}

// The one second floor in SweepInactiveRelays is deliberate: it stops a zero or
// near-zero ttl from marking every relay inactive at once. Nothing guarded it
// before this test.
func TestSweepFloorsSubSecondTTL(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	var id string
	if err := pool.QueryRow(ctx,
		`INSERT INTO relay_nodes (id, api_key_hash, endpoint, region, role, status, last_heartbeat)
		 VALUES (gen_random_uuid(), $1, '10.0.0.77:9001', 'us-east', 'guard', 'active', NOW())
		 RETURNING id`,
		"test-hash-floor-"+time.Now().Format("150405.000000"),
	).Scan(&id); err != nil {
		t.Fatalf("seed: %v", err)
	}
	cleanupRow(t, pool, deleteRelayByID, id)

	if _, err := SweepInactiveRelays(ctx, pool, time.Nanosecond); err != nil {
		t.Fatalf("Sweep: %v", err)
	}

	if got := relayStatus(t, pool, id); got != "active" {
		t.Errorf("a relay heartbeated just now was swept by a 1ns ttl: status = %q, want active", got)
	}
}

// Per SECURITY_MODEL §9: this exclusion mechanism is how the circuit-route handler
// guarantees three distinct physical hops. The contract under test is exclusion, so
// the assertions cover the excluded set, the role and the status. They deliberately
// do not assert that the pick comes from this test's own rows: the picker ranges
// over every active guard in the database, so such an assertion would fail whenever
// another package seeds one during the same run, with nothing broken in the code.
func TestPickRandomActiveByRoleExcludesIDs(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	seedActiveGuard := func(tag string) string {
		var id string
		if err := pool.QueryRow(ctx,
			`INSERT INTO relay_nodes (id, api_key_hash, endpoint, region, role, status, last_heartbeat)
			 VALUES (gen_random_uuid(), $1, '10.0.0.99:9001', 'us-east', 'guard', 'active', NOW())
			 RETURNING id`,
			"test-hash-exclude-"+tag+"-"+time.Now().Format("150405.000000"),
		).Scan(&id); err != nil {
			t.Fatalf("seed guard %s: %v", tag, err)
		}
		cleanupRow(t, pool, deleteRelayByID, id)
		return id
	}

	g1 := seedActiveGuard("a")
	g2 := seedActiveGuard("b")

	assertEligible := func(r *Relay, excluded ...string) {
		t.Helper()
		if r.Role != "guard" {
			t.Errorf("picked role %q, want guard", r.Role)
		}
		if r.Status != "active" {
			t.Errorf("picked status %q, want active", r.Status)
		}
		for _, x := range excluded {
			if r.ID == x {
				t.Errorf("picked %q, which was excluded", r.ID)
			}
		}
	}

	r, err := PickRandomActiveByRole(ctx, pool, "guard")
	if err != nil {
		t.Fatalf("unexpected error with no exclusions: %v", err)
	}
	assertEligible(r)

	r, err = PickRandomActiveByRole(ctx, pool, "guard", g1)
	if err != nil {
		t.Fatalf("unexpected error excluding g1: %v", err)
	}
	assertEligible(r, g1)

	// Excluding both seeded guards is satisfied either by an error, when nothing
	// else active remains, or by some other eligible guard. Both are correct. What
	// must never happen is an excluded id coming back.
	r, err = PickRandomActiveByRole(ctx, pool, "guard", g1, g2)
	if err == nil {
		assertEligible(r, g1, g2)
	}
}

func TestProvisionRejectsInvalidRole(t *testing.T) {
	// No DB needed: the role check happens before any query.
	_, _, err := ProvisionRelay(context.Background(), nil, "salt", "endpoint", "region", "admin")
	if err != ErrInvalidRole {
		t.Errorf("expected ErrInvalidRole, got %v", err)
	}
}
