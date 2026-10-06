package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ChronoCoders/darkrouter/authority/internal/auth"
)

// routeRequest builds the request HandleRoute expects. The subscriber id goes into
// the context the way Authenticate puts it there. Without it the handler answers
// 401 at its first line and never reaches relay selection, which is how both tests
// in this file used to pass nothing while claiming to test hop distinctness.
func routeRequest(subID string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/circuits/route", nil)
	return req.WithContext(context.WithValue(req.Context(), subscriberKey, subID))
}

func serveRoute(pool *pgxpool.Pool, subID string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	NewCircuitHandler(pool).HandleRoute(rec, routeRequest(subID))
	return rec
}

// Per SECURITY_MODEL §9: the same host serving two hops collapses the
// unlinkability between client IP and destination. Two distinct nodes are seeded
// and the third pick has no eligible row once the first two ids are excluded, so
// the whole request must fail rather than reuse a node.
func TestCircuitRouteRequiresThreeDistinctNodes(t *testing.T) {
	pool := testPool(t, "TEST_DATABASE_URL not set; skipping DB-backed distinct-host test")
	subID := seedSubscriberWithActiveSubscription(t, pool, "distinct")

	requireNoActiveRelays(t, pool, "exit")
	seedActiveRelay(t, pool, "guard", "distinct")
	seedActiveRelay(t, pool, "middle", "distinct")

	rec := serveRoute(pool, subID)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when exit role has no row, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestCircuitRouteRequiresAllThreeRoles(t *testing.T) {
	pool := testPool(t, "TEST_DATABASE_URL not set; skipping DB-backed circuit route test")
	subID := seedSubscriberWithActiveSubscription(t, pool, "roles")

	requireNoActiveRelays(t, pool, "exit")
	seedActiveRelay(t, pool, "guard", "roles")
	seedActiveRelay(t, pool, "middle", "roles")

	if rec := serveRoute(pool, subID); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 with missing exit role, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	seedActiveRelay(t, pool, "exit", "roles")

	rec := serveRoute(pool, subID)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 once all three roles are available, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var got circuitRouteResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Guard.ID == "" || got.Middle.ID == "" || got.Exit.ID == "" {
		t.Fatalf("missing hop ids: %+v", got)
	}
	if got.Guard.ID == got.Middle.ID || got.Middle.ID == got.Exit.ID || got.Guard.ID == got.Exit.ID {
		t.Fatalf("relays must come from distinct rows: %+v", got)
	}
}

// The two tests above inject the subscriber id directly, which is the right unit
// boundary for HandleRoute but says nothing about the route being wired behind
// Authenticate. This covers that wiring: the same route, mounted the way
// cmd/authority mounts it, must reject a request carrying no credentials.
func TestCircuitRouteRejectsUnauthenticatedThroughRouter(t *testing.T) {
	pool := testPool(t, "TEST_DATABASE_URL not set; skipping DB-backed router wiring test")

	ch := NewCircuitHandler(pool)
	r := chi.NewRouter()
	r.Group(func(r chi.Router) {
		r.Use(Authenticate(auth.NewJWTManager(testJWTSecret), pool))
		r.Get("/api/v1/circuits/route", ch.HandleRoute)
	})

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/circuits/route", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("an unauthenticated request reached past Authenticate: got %d (body=%s)",
			rec.Code, rec.Body.String())
	}
}
