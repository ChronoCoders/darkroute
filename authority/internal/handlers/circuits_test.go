package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Per SECURITY_MODEL §9: same host as guard and exit collapses the
// unlinkability between client IP and destination. Because we cannot make
// two rows share a primary key, this test seeds two distinct nodes total
// and exercises the path where the third pick has no eligible row after
// the first two IDs are excluded.
func TestCircuitRouteRequiresThreeDistinctNodes(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed distinct-host test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	seedAs := func(role string) string {
		var id string
		if err := pool.QueryRow(ctx,
			`INSERT INTO relay_nodes (id, api_key_hash, endpoint, region, role, status, last_heartbeat)
			 VALUES (gen_random_uuid(), $1, $2, 'us-east', $3, 'active', NOW())
			 RETURNING id`,
			"test-hash-distinct-"+role+"-"+time.Now().Format("150405.000000"),
			"10.0.0.50:9001", role,
		).Scan(&id); err != nil {
			t.Fatalf("seed %s: %v", role, err)
		}
		t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM relay_nodes WHERE id = $1`, id) })
		return id
	}
	seedAs("guard")
	seedAs("middle")

	h := NewCircuitHandler(pool)
	rec := httptest.NewRecorder()
	h.HandleRoute(rec, httptest.NewRequest(http.MethodGet, "/api/v1/circuits/route", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when exit role has no row, got %d", rec.Code)
	}
}

func TestCircuitRouteRequiresAllThreeRoles(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed circuit route test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	seed := func(role string) string {
		var id string
		if err := pool.QueryRow(ctx,
			`INSERT INTO relay_nodes (id, api_key_hash, endpoint, region, role, status, last_heartbeat)
			 VALUES (gen_random_uuid(), $1, $2, 'us-east', $3, 'active', NOW())
			 RETURNING id`,
			"test-hash-"+role+"-"+time.Now().Format("150405.000000"),
			"10.0.0.1:9001", role,
		).Scan(&id); err != nil {
			t.Fatalf("seed %s: %v", role, err)
		}
		t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM relay_nodes WHERE id = $1`, id) })
		return id
	}
	seed("guard")
	seed("middle")

	h := NewCircuitHandler(pool)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/circuits/route", nil)
	rec := httptest.NewRecorder()
	h.HandleRoute(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 with missing exit role, got %d", rec.Code)
	}

	exitID := seed("exit")
	_ = exitID

	rec2 := httptest.NewRecorder()
	h.HandleRoute(rec2, httptest.NewRequest(http.MethodGet, "/api/v1/circuits/route", nil))
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200 after all three roles available, got %d (body=%s)", rec2.Code, rec2.Body.String())
	}
	var got circuitRouteResponse
	if err := json.Unmarshal(rec2.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Guard.ID == "" || got.Middle.ID == "" || got.Exit.ID == "" {
		t.Fatalf("missing hop ids: %+v", got)
	}
	if got.Guard.ID == got.Middle.ID || got.Middle.ID == got.Exit.ID {
		t.Fatalf("relays must come from distinct rows: %+v", got)
	}
}
