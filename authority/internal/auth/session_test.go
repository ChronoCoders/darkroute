package auth

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed session test")
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

func TestSessionCreateGetDelete(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()

	ctx := context.Background()
	var subID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO subscribers (email, password) VALUES ($1, $2) RETURNING id`,
		"session-test-"+time.Now().Format("150405.000000")+"@example.test", "x").Scan(&subID); err != nil {
		t.Fatalf("insert subscriber: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM subscribers WHERE id = $1`, subID)
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
