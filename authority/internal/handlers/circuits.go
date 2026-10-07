package handlers

import (
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ChronoCoders/quiethop/authority/internal/relay"
)

// SECURITY_MODEL §9 lets the authority know circuit routes. This is the
// one place that information is intentionally produced.
type CircuitHandler struct {
	pool *pgxpool.Pool
}

func NewCircuitHandler(pool *pgxpool.Pool) *CircuitHandler {
	return &CircuitHandler{pool: pool}
}

// circuitHop carries an IP literal and a separate TLS name. The client dials
// ip:port and sends tls_name as SNI, so no name is resolved while a path is
// constructed (SECURITY_MODEL 5.3). static_pubkey is hex; it is public key
// material and the client pins the NK handshake to it.
type circuitHop struct {
	ID           string `json:"id"`
	IP           string `json:"ip"`
	Port         int    `json:"port"`
	TLSName      string `json:"tls_name"`
	Region       string `json:"region"`
	StaticPubkey string `json:"static_pubkey"`
}

func hopOf(r *relay.Relay) circuitHop {
	return circuitHop{
		ID:           r.ID,
		IP:           r.IP,
		Port:         r.Port,
		TLSName:      r.TLSName,
		Region:       r.Region,
		StaticPubkey: r.StaticPubkeyHex(),
	}
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

	// The three picks are separated by role, and that is all they guarantee: three
	// distinct relay ids. relay_nodes carries one role per row, so a row picked for
	// one role is never eligible for another.
	//
	// Distinct ids are not distinct hosts. endpoint carries no unique constraint, so
	// one machine can be registered as a guard, a middle and an exit, and a circuit
	// can pass through that machine three times. Nothing here prevents it. Host
	// distinctness belongs to client path selection against the signed registry, per
	// SECURITY_MODEL 5.3.
	//
	// If any pick finds no eligible relay, the whole request fails with 503.
	guard, err := relay.PickRandomActiveByRole(r.Context(), h.pool, "guard")
	if err != nil {
		writeRouteError(w, err)
		return
	}
	// The excluded ids on this pick and the next cannot change either outcome while
	// role is a single column per row: a row with role middle or exit can never
	// carry a guard's id. They stay because path selection is moving to the client
	// and this handler is to be removed rather than reworked.
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
		Guard:  hopOf(guard),
		Middle: hopOf(middle),
		Exit:   hopOf(exit),
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
