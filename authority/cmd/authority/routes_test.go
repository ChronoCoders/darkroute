package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// tableOf walks the real route table and returns "METHOD pattern" for each
// registered route.
//
// A walk of the production table is the point. Rebuilding the list inside the
// test would only prove the copy matches itself, which is exactly how a route
// gets removed from the map and left registered in the binary.
func tableOf(t *testing.T) []string {
	t.Helper()
	// Every dependency is nil. Walking the table never calls a handler, and a
	// nil here would surface as a panic if one were called, which is a louder
	// failure than a silent pass.
	r := routes(routeDeps{})
	var out []string
	err := chi.Walk(r, func(method string, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		out = append(out, method+" "+route)
		return nil
	})
	if err != nil {
		t.Fatalf("walk the route table: %v", err)
	}
	return out
}

// Route assignment is removed, so nothing may serve those paths
// (SECURITY_MODEL 5.3, docs/DECISIONS.md entry 5).
func TestRouteAssignmentIsNotRegistered(t *testing.T) {
	table := tableOf(t)

	// Control first. An empty or broken walk would make the absence check below
	// pass while proving nothing, so the routes that must exist are asserted in
	// the same table.
	for _, want := range []string{
		"GET /api/v1/registry",
		"GET /api/v1/account",
		"GET /api/v1/usage",
		"POST /api/v1/tokens/issue",
	} {
		if !contains(table, want) {
			t.Fatalf("control failed: %q is missing, so this table proves nothing about absence. table: %v", want, table)
		}
	}

	for _, route := range table {
		if strings.Contains(route, "/circuits") {
			t.Errorf("route assignment is still registered: %q", route)
		}
	}
}

// The removed paths answer 404, and they do so for an authenticated request
// too. A route left registered behind the session middleware answers 401, which
// an unauthenticated-only check would read as gone.
func TestRemovedCircuitPathsReturn404(t *testing.T) {
	srv := httptest.NewServer(routes(routeDeps{}))
	defer srv.Close()

	for _, path := range []string{"/api/v1/circuits/route", "/api/v1/circuits"} {
		for _, withSession := range []bool{false, true} {
			req, err := http.NewRequest(http.MethodGet, srv.URL+path, nil)
			if err != nil {
				t.Fatal(err)
			}
			if withSession {
				req.Header.Set("Authorization", "Bearer irrelevant")
				req.AddCookie(&http.Cookie{Name: "session_id", Value: "irrelevant"})
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("%s (session=%v): %v", path, withSession, err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("%s (session=%v) returned %d, want 404", path, withSession, resp.StatusCode)
			}
		}
	}
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
