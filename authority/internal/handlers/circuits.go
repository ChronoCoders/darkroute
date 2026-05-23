package handlers

import (
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dslabs/darkroute/authority/internal/relay"
)

// SECURITY_MODEL §9 lets the authority know circuit routes — this is the
// one place that information is intentionally produced.
type CircuitHandler struct {
	pool *pgxpool.Pool
}

func NewCircuitHandler(pool *pgxpool.Pool) *CircuitHandler {
	return &CircuitHandler{pool: pool}
}

type circuitHop struct {
	ID       string `json:"id"`
	Endpoint string `json:"endpoint"`
	Region   string `json:"region"`
}

type circuitRouteResponse struct {
	Guard  circuitHop `json:"guard"`
	Middle circuitHop `json:"middle"`
	Exit   circuitHop `json:"exit"`
}

func (h *CircuitHandler) HandleRoute(w http.ResponseWriter, r *http.Request) {
	subID, ok := r.Context().Value(subscriberKey).(string)
	if !ok || subID == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	// Phase 5 onboarding gate: only subscriptions with status='active'
	// can be assigned circuits. pending_review or any other state is
	// rejected with 403 so the user-facing dashboard can display a
	// distinct "pending review" surface.
	var status string
	if err := h.pool.QueryRow(r.Context(),
		`SELECT status FROM subscriptions
		 WHERE subscriber_id = $1
		 ORDER BY created_at DESC LIMIT 1`,
		subID,
	).Scan(&status); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "no_active_subscription"})
		return
	}
	if status != "active" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "no_active_subscription"})
		return
	}

	// SECURITY_MODEL §9 requires three distinct physical relays across
	// guard/middle/exit. Each pick excludes IDs already chosen so the
	// same node can never serve two roles in the same circuit; if any
	// pick has no eligible relay (because the eligible pool is empty
	// after exclusion), the whole request fails with 503.
	guard, err := relay.PickRandomActiveByRole(r.Context(), h.pool, "guard")
	if err != nil {
		writeRouteError(w, err)
		return
	}
	middle, err := relay.PickRandomActiveByRole(r.Context(), h.pool, "middle", guard.ID)
	if err != nil {
		writeRouteError(w, err)
		return
	}
	exit, err := relay.PickRandomActiveByRole(r.Context(), h.pool, "exit", guard.ID, middle.ID)
	if err != nil {
		writeRouteError(w, err)
		return
	}
	if _, err := h.pool.Exec(r.Context(),
		`INSERT INTO circuit_assignments (subscriber_id, guard_id, middle_id, exit_id)
		 VALUES ($1, $2, $3, $4)`,
		subID, guard.ID, middle.ID, exit.ID,
	); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	writeJSON(w, http.StatusOK, circuitRouteResponse{
		Guard:  circuitHop{ID: guard.ID, Endpoint: guard.Endpoint, Region: guard.Region},
		Middle: circuitHop{ID: middle.ID, Endpoint: middle.Endpoint, Region: middle.Region},
		Exit:   circuitHop{ID: exit.ID, Endpoint: exit.Endpoint, Region: exit.Region},
	})
}

type circuitListItem struct {
	ID        string `json:"id"`
	GuardID   string `json:"guard_id"`
	MiddleID  string `json:"middle_id"`
	ExitID    string `json:"exit_id"`
	CreatedAt string `json:"created_at"`
}

type circuitListResponse struct {
	Recent []circuitListItem `json:"recent"`
}

// Only IDs are returned, never relay endpoints or destinations.
func (h *CircuitHandler) HandleListCircuits(w http.ResponseWriter, r *http.Request) {
	subID, ok := r.Context().Value(subscriberKey).(string)
	if !ok || subID == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	rows, err := h.pool.Query(r.Context(),
		`SELECT id, guard_id, middle_id, exit_id, created_at
		 FROM circuit_assignments
		 WHERE subscriber_id = $1
		 ORDER BY created_at DESC
		 LIMIT 50`,
		subID,
	)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	defer rows.Close()
	out := circuitListResponse{Recent: []circuitListItem{}}
	for rows.Next() {
		var item circuitListItem
		var created time.Time
		if err := rows.Scan(&item.ID, &item.GuardID, &item.MiddleID, &item.ExitID, &created); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
			return
		}
		item.CreatedAt = created.UTC().Format(time.RFC3339)
		out.Recent = append(out.Recent, item)
	}
	if err := rows.Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func writeRouteError(w http.ResponseWriter, err error) {
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "no_active_relay"})
		return
	}
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
}
