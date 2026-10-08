package handlers

import (
	"context"
	"testing"
	"time"

	"encoding/hex"
	"github.com/ChronoCoders/quiethop/authority/internal/dbtest"
	"github.com/ChronoCoders/quiethop/authority/internal/relay"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Shared database plumbing for this package's tests. It exists so the pool is
// closed in the right order in one place rather than in each test.
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
	deleteRelayByID      = `DELETE FROM relay_nodes WHERE id = $1`
	deleteSubscriberByID = `DELETE FROM subscribers WHERE id = $1`
)

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

// cleanupRelay removes a relay the test created.
//
// It used to clear circuit_assignments rows first, because a successful route
// persisted one referencing all three relays and three foreign keys then blocked
// the deletes. Migration 009 dropped that table with route assignment, so the
// references no longer exist and the delete stands on its own.
func cleanupRelay(t *testing.T, pool *pgxpool.Pool, id string) {
	t.Helper()
	t.Cleanup(func() {
		ctx := context.Background()
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

func reqCtx() context.Context {
	return context.Background()
}

func hexOf(b []byte) string {
	return hex.EncodeToString(b)
}

// provisionForTest creates a relay with a known static public key and returns
// its id and plaintext API key. The key is public material, so a fixed value
// is safe; no private key is generated or written by any test here.
func provisionForTest(t *testing.T, pool *pgxpool.Pool, salt string, pubkey []byte) (string, string) {
	t.Helper()
	id, apiKey, err := relay.ProvisionRelay(
		reqCtx(), pool, salt,
		"pin.test", "us-east", "guard",
		"10.0.0.70", 9001, pubkey,
		"op-test", "host-test",
	)
	if err != nil {
		t.Fatalf("ProvisionRelay: %v", err)
	}
	cleanupRelay(t, pool, id)
	return id, apiKey
}

func relayStatusByID(t *testing.T, pool *pgxpool.Pool, id string) string {
	t.Helper()
	var status string
	if err := pool.QueryRow(reqCtx(),
		`SELECT status FROM relay_nodes WHERE id = $1`, id).Scan(&status); err != nil {
		t.Fatalf("read status for %s: %v", id, err)
	}
	return status
}
