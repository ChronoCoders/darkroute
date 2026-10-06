package handlers

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Shared database plumbing for this package's tests. It exists so the pool is
// closed in the right order in one place rather than in each test.
func testPool(t *testing.T, skipMsg string) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip(skipMsg)
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
	// Registered before any caller registers a row cleanup, so LIFO closes the
	// pool last. A deferred Close runs before every t.Cleanup, which silently
	// broke every row delete in this package and let rows build up across runs.
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

const (
	deleteRelayByID                   = `DELETE FROM relay_nodes WHERE id = $1`
	deleteSubscriberByID              = `DELETE FROM subscribers WHERE id = $1`
	deleteAssignmentsReferencingRelay = `DELETE FROM circuit_assignments
		 WHERE guard_id = $1 OR middle_id = $1 OR exit_id = $1`
)

// seedSubscriberWithActiveSubscription creates the subscriber and the active
// subscription that the circuit route handler requires before it reaches any relay
// selection. Every dependent table cascades from subscribers, so one delete is
// enough to undo all of it.
func seedSubscriberWithActiveSubscription(t *testing.T, pool *pgxpool.Pool, tag string) string {
	t.Helper()
	return seedSubscriberWithSubscription(t, pool, tag, "active")
}

// The status is a parameter because the onboarding gate turns on it: a new subscriber
// sits at pending_review until an admin approves, and that path needs covering as much
// as the active one does.
func seedSubscriberWithSubscription(t *testing.T, pool *pgxpool.Pool, tag, status string) string {
	t.Helper()
	ctx := context.Background()
	var subID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO subscribers (email, password) VALUES ($1, $2) RETURNING id`,
		tag+"-"+time.Now().Format("150405.000000")+"@example.test", "x",
	).Scan(&subID); err != nil {
		t.Fatalf("seed subscriber: %v", err)
	}
	cleanupRow(t, pool, deleteSubscriberByID, subID)
	if _, err := pool.Exec(ctx,
		`INSERT INTO subscriptions (subscriber_id, tier, status, current_period_start, current_period_end)
		 VALUES ($1, 'free', $2, NOW(), NOW() + INTERVAL '30 days')`, subID, status,
	); err != nil {
		t.Fatalf("seed %s subscription: %v", status, err)
	}
	return subID
}

// cleanupRelay removes a relay the test created, together with any circuit
// assignment that references it. A successful route persists an assignment row
// pointing at all three relays, and three foreign keys then block the relay
// deletes. Clearing the references inside this one cleanup keeps it independent of
// the order the seeds were registered in; a separately registered cleanup only
// works if it happens to be registered after every relay, which is a trap.
func cleanupRelay(t *testing.T, pool *pgxpool.Pool, id string) {
	t.Helper()
	t.Cleanup(func() {
		ctx := context.Background()
		if _, err := pool.Exec(ctx, deleteAssignmentsReferencingRelay, id); err != nil {
			t.Errorf("cleanup assignments referencing relay %s: %v", id, err)
			return
		}
		tag, err := pool.Exec(ctx, deleteRelayByID, id)
		if err != nil {
			t.Errorf("cleanup relay %s: %v", id, err)
			return
		}
		if tag.RowsAffected() != 1 {
			t.Errorf("cleanup relay %s removed %d rows, want 1", id, tag.RowsAffected())
		}
	})
}

func seedActiveRelay(t *testing.T, pool *pgxpool.Pool, role, tag string) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO relay_nodes (id, api_key_hash, endpoint, region, role, status, last_heartbeat)
		 VALUES (gen_random_uuid(), $1, $2, 'us-east', $3, 'active', NOW())
		 RETURNING id`,
		"test-hash-"+tag+"-"+role+"-"+time.Now().Format("150405.000000"),
		"10.0.0.50:9001", role,
	).Scan(&id); err != nil {
		t.Fatalf("seed %s relay: %v", role, err)
	}
	cleanupRelay(t, pool, id)
	return id
}

// countActiveRelays is used as an explicit precondition. These tests assert a 503
// that depends on no eligible relay existing for one role, which is a statement
// about the whole table, so the precondition is checked rather than assumed. If it
// fails, the message names cross-package contamination instead of leaving a
// mysterious 200.
func countActiveRelays(t *testing.T, pool *pgxpool.Pool, role string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM relay_nodes WHERE role = $1 AND status = 'active'`, role,
	).Scan(&n); err != nil {
		t.Fatalf("count active %s relays: %v", role, err)
	}
	return n
}

func requireNoActiveRelays(t *testing.T, pool *pgxpool.Pool, role string) {
	t.Helper()
	if n := countActiveRelays(t, pool, role); n != 0 {
		t.Fatalf("precondition: %d active %s relays already exist, so this test cannot "+
			"observe the no-eligible-relay path. Another package or a previous run left "+
			"rows behind.", n, role)
	}
}
