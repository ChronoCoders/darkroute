package handlers

import (
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dslabs/darkroute/authority/internal/relay"
)

// CircuitHandler serves circuit-assignment requests from authenticated
// operators. The authority assigns one active relay per role uniformly at
// random; if any role has no active relay, the request fails with 503.
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
	writeJSON(w, http.StatusOK, circuitRouteResponse{
		Guard:  circuitHop{ID: guard.ID, Endpoint: guard.Endpoint, Region: guard.Region},
		Middle: circuitHop{ID: middle.ID, Endpoint: middle.Endpoint, Region: middle.Region},
		Exit:   circuitHop{ID: exit.ID, Endpoint: exit.Endpoint, Region: exit.Region},
	})
}

func writeRouteError(w http.ResponseWriter, err error) {
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "no_active_relay"})
		return
	}
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
}
