package auth

import (
	"context"
	"testing"
	"time"

	"github.com/ChronoCoders/darkrouter/authority/internal/dbtest"
	"github.com/jackc/pgx/v5/pgxpool"
)

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
	// Registered before the caller registers any row cleanup, so LIFO closes the
	// pool last. A deferred Close runs before every t.Cleanup, which silently broke
	// the row delete below and let subscribers build up across runs.
	t.Cleanup(pool.Close)
	return pool
}

func TestSessionCreateGetDelete(t *testing.T) {
	pool := testPool(t)

	ctx := context.Background()
	var subID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO subscribers (email, password) VALUES ($1, $2) RETURNING id`,
		"session-test-"+time.Now().Format("150405.000000")+"@example.test", "x").Scan(&subID); err != nil {
		t.Fatalf("insert subscriber: %v", err)
	}
	t.Cleanup(func() {
		tag, err := pool.Exec(ctx, `DELETE FROM subscribers WHERE id = $1`, subID)
		if err != nil {
			t.Errorf("cleanup subscriber %s: %v", subID, err)
			return
		}
		if tag.RowsAffected() != 1 {
			t.Errorf("cleanup subscriber %s removed %d rows, want 1", subID, tag.RowsAffected())
		}
	})

	sid, err := CreateSession(ctx, pool, subID)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	got, err := GetSession(ctx, pool, sid)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.SubscriberID != subID {
		t.Errorf("got subscriber %q want %q", got.SubscriberID, subID)
	}
	if got.ExpiresAt.Before(time.Now().Add(7 * time.Hour)) {
		t.Errorf("expires_at should be ~8h in the future, got %v", got.ExpiresAt)
	}
	if err := DeleteSession(ctx, pool, sid); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	if _, err := GetSession(ctx, pool, sid); err == nil {
		t.Errorf("expected GetSession to fail after delete")
	}
}
