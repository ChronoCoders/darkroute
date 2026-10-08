package relay

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ChronoCoders/quiethop/authority/internal/dbtest"
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
	// Lazy: this is where the package's database gets created, on the first test that
	// asks for one. A failure is fatal rather than a skip, because a skipped database
	// test and a passing one read the same in a test log.
	url, err := dbtest.URL()
	if err != nil {
		t.Fatalf("test database: %v", err)
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

	id, plaintext, err := ProvisionRelay(ctx, pool, "test-salt-1234567890", "node.test", "us-east", "guard", "10.0.0.50", 9001, testPubkey(), "op-a", "host-a")
	if err != nil {
		t.Fatalf("ProvisionRelay: %v", err)
	}
	cleanupRow(t, pool, deleteRelayByID, id)
	if !strings.ContainsAny(plaintext, "0123456789abcdef") || len(plaintext) != 64 {
		t.Errorf("plaintext key not 64-char hex: %q", plaintext)
	}

	gotID, err := RecordHeartbeat(ctx, pool, "test-salt-1234567890", plaintext, nil)
	if err != nil {
		t.Fatalf("RecordHeartbeat: %v", err)
	}
	if gotID != id {
		t.Errorf("heartbeat returned id %q want %q", gotID, id)
	}

	if _, err := RecordHeartbeat(ctx, pool, "test-salt-1234567890", "wrong-key", nil); err == nil {
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
		`INSERT INTO relay_nodes (id, api_key_hash, tls_name, region, role, status, last_heartbeat, ip, port, static_pubkey, operator_id, host_id)
		 VALUES (gen_random_uuid(), $1, 'floor.test', 'us-east', 'guard', 'active', NOW(), '10.0.0.77', 9001, decode(repeat('ab', 32), 'hex'), 'op-floor', 'host-floor')
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
			`INSERT INTO relay_nodes (id, api_key_hash, tls_name, region, role, status, last_heartbeat, ip, port, static_pubkey, operator_id, host_id)
			 VALUES (gen_random_uuid(), $1, 'exclude.test', 'us-east', 'guard', 'active', NOW(), '10.0.0.99', 9001, decode(repeat('ab', 32), 'hex'), 'op-ex', 'host-ex-' || $1)
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
	_, _, err := ProvisionRelay(context.Background(), nil, "salt", "node.test", "region", "admin", "10.0.0.1", 443, testPubkey(), "op-a", "host-a")
	if err != ErrInvalidRole {
		t.Errorf("expected ErrInvalidRole, got %v", err)
	}
}

// testPubkey returns a fixed 32-byte static public key. Public key material, so
// a constant is safe. No test in this package generates or writes a private key.
func testPubkey() []byte {
	key := make([]byte, StaticKeyLen)
	for i := range key {
		key[i] = 0xAB
	}
	return key
}

// TestHeartbeatPinsStaticKey covers the three ways a heartbeat can present a
// static public key: matching, mismatched and absent. SECURITY_MODEL 7.2 makes
// the key immutable after provisioning, so a mismatch must change nothing.
func TestHeartbeatPinsStaticKey(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	const salt = "test-salt-pinning-00"

	id, plaintext, err := ProvisionRelay(ctx, pool, salt, "pin.test", "us-east", "guard", "10.0.0.60", 9001, testPubkey(), "op-a", "host-a")
	if err != nil {
		t.Fatalf("ProvisionRelay: %v", err)
	}
	cleanupRow(t, pool, deleteRelayByID, id)

	// Matching key: accepted, relay becomes active.
	gotID, err := RecordHeartbeat(ctx, pool, salt, plaintext, testPubkey())
	if err != nil {
		t.Fatalf("matching key rejected: %v", err)
	}
	if gotID != id {
		t.Errorf("matching key returned id %q, want %q", gotID, id)
	}
	if got := relayStatus(t, pool, id); got != "active" {
		t.Fatalf("after a matching heartbeat status = %q, want active", got)
	}

	// Park it inactive so a rejected heartbeat has something to fail to change.
	if _, err := pool.Exec(ctx, `UPDATE relay_nodes SET status = 'inactive' WHERE id = $1`, id); err != nil {
		t.Fatalf("park inactive: %v", err)
	}

	// Mismatched key: rejected, nothing updated, the id comes back for logging.
	wrong := testPubkey()
	wrong[0] ^= 0xFF
	mismatchID, err := RecordHeartbeat(ctx, pool, salt, plaintext, wrong)
	if !errors.Is(err, ErrStaticKeyMismatch) {
		t.Fatalf("mismatched key: err = %v, want ErrStaticKeyMismatch", err)
	}
	if mismatchID != id {
		t.Errorf("mismatch returned id %q, want %q for the log line", mismatchID, id)
	}
	if got := relayStatus(t, pool, id); got != "inactive" {
		t.Errorf("a rejected heartbeat marked the relay %q, want it left inactive", got)
	}

	// The stored key is untouched.
	var stored []byte
	if err := pool.QueryRow(ctx, `SELECT static_pubkey FROM relay_nodes WHERE id = $1`, id).Scan(&stored); err != nil {
		t.Fatalf("read back stored key: %v", err)
	}
	if !bytes.Equal(stored, testPubkey()) {
		t.Error("a rejected heartbeat changed the stored static public key")
	}

	// Absent key: accepted, because the field is optional.
	if _, err := RecordHeartbeat(ctx, pool, salt, plaintext, nil); err != nil {
		t.Fatalf("absent key rejected: %v", err)
	}
	if got := relayStatus(t, pool, id); got != "active" {
		t.Errorf("after a keyless heartbeat status = %q, want active", got)
	}
}

func TestHeartbeatRejectsWrongLengthKey(t *testing.T) {
	// No DB needed: the length check runs before any query.
	_, err := RecordHeartbeat(context.Background(), nil, "salt", "key", []byte{1, 2, 3})
	if !errors.Is(err, ErrInvalidStaticKey) {
		t.Errorf("err = %v, want ErrInvalidStaticKey", err)
	}
}

func TestProvisionRejectsBadKeyAndAddress(t *testing.T) {
	ctx := context.Background()
	if _, _, err := ProvisionRelay(ctx, nil, "salt", "n.test", "r", "guard", "10.0.0.1", 443, []byte{1}, "op-a", "host-a"); !errors.Is(err, ErrInvalidStaticKey) {
		t.Errorf("short key: err = %v, want ErrInvalidStaticKey", err)
	}
	if _, _, err := ProvisionRelay(ctx, nil, "salt", "n.test", "r", "guard", "not-an-ip", 443, testPubkey(), "op-a", "host-a"); !errors.Is(err, ErrInvalidAddress) {
		t.Errorf("bad ip: err = %v, want ErrInvalidAddress", err)
	}
	for _, port := range []int{0, 65536} {
		if _, _, err := ProvisionRelay(ctx, nil, "salt", "n.test", "r", "guard", "10.0.0.1", port, testPubkey(), "op-a", "host-a"); !errors.Is(err, ErrInvalidAddress) {
			t.Errorf("port %d: err = %v, want ErrInvalidAddress", port, err)
		}
	}
}

func TestProvisionRequiresOperatorAndHostIdentifiers(t *testing.T) {
	// No DB needed: the check runs before any query. Both identifiers are
	// assigned by the authority, so an empty one is a caller bug, not a relay
	// claim that could be validated later.
	ctx := context.Background()
	for _, tc := range []struct{ op, host string }{
		{"", "host-a"},
		{"op-a", ""},
		{"", ""},
	} {
		_, _, err := ProvisionRelay(ctx, nil, "salt", "n.test", "r", "guard",
			"10.0.0.1", 443, testPubkey(), tc.op, tc.host)
		if !errors.Is(err, ErrMissingIdentifier) {
			t.Errorf("operator_id=%q host_id=%q: err = %v, want ErrMissingIdentifier", tc.op, tc.host, err)
		}
	}
}

func TestProvisionStoresOperatorAndHostIdentifiers(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	id, _, err := ProvisionRelay(ctx, pool, "test-salt-ids-000000", "ids.test", "us-east",
		"guard", "10.0.0.80", 9001, testPubkey(), "op-zeta", "host-omega")
	if err != nil {
		t.Fatalf("ProvisionRelay: %v", err)
	}
	cleanupRow(t, pool, deleteRelayByID, id)

	var op, host string
	if err := pool.QueryRow(ctx,
		`SELECT operator_id, host_id FROM relay_nodes WHERE id = $1`, id).Scan(&op, &host); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if op != "op-zeta" || host != "host-omega" {
		t.Errorf("stored operator_id=%q host_id=%q, want op-zeta/host-omega", op, host)
	}
}
