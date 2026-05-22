package handlers

import (
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// AccountHandler serves the operator dashboard's account and usage
// surfaces. Both endpoints are read-only and scoped to the authenticated
// subscriber; no admin-only data is reachable here.
type AccountHandler struct {
	pool *pgxpool.Pool
}

func NewAccountHandler(pool *pgxpool.Pool) *AccountHandler {
	return &AccountHandler{pool: pool}
}

type subscriptionInfo struct {
	Tier               string `json:"tier"`
	Status             string `json:"status"`
	TokensIssued       int64  `json:"tokens_issued"`
	BandwidthUsed      int64  `json:"bandwidth_used"`
	CurrentPeriodStart string `json:"current_period_start"`
	CurrentPeriodEnd   string `json:"current_period_end"`
}

type accountResponse struct {
	ID           string           `json:"id"`
	Email        string           `json:"email"`
	Role         string           `json:"role"`
	CreatedAt    string           `json:"created_at"`
	Subscription subscriptionInfo `json:"subscription"`
}

func (h *AccountHandler) HandleGetAccount(w http.ResponseWriter, r *http.Request) {
	subID, ok := r.Context().Value(subscriberKey).(string)
	if !ok || subID == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	var email, role string
	var subCreatedAt time.Time
	if err := h.pool.QueryRow(r.Context(),
		`SELECT email, role, created_at FROM subscribers WHERE id = $1`, subID,
	).Scan(&email, &role, &subCreatedAt); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}

	var info subscriptionInfo
	var periodStart, periodEnd time.Time
	if err := h.pool.QueryRow(r.Context(),
		`SELECT tier, status, tokens_issued, bandwidth_used,
		        current_period_start, current_period_end
		 FROM subscriptions
		 WHERE subscriber_id = $1
		 ORDER BY created_at DESC LIMIT 1`, subID,
	).Scan(&info.Tier, &info.Status, &info.TokensIssued, &info.BandwidthUsed,
		&periodStart, &periodEnd); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	info.CurrentPeriodStart = periodStart.UTC().Format(time.RFC3339)
	info.CurrentPeriodEnd = periodEnd.UTC().Format(time.RFC3339)

	writeJSON(w, http.StatusOK, accountResponse{
		ID:           subID,
		Email:        email,
		Role:         role,
		CreatedAt:    subCreatedAt.UTC().Format(time.RFC3339),
		Subscription: info,
	})
}

type relayRoleCounts struct {
	Guard  int `json:"guard"`
	Middle int `json:"middle"`
	Exit   int `json:"exit"`
}

type usageResponse struct {
	TokensIssued        int64           `json:"tokens_issued"`
	BandwidthUsed       int64           `json:"bandwidth_used"`
	CircuitsAssigned    int64           `json:"circuits_assigned"`
	ActiveRelays        relayRoleCounts `json:"active_relays"`
	CurrentPeriodStart  string          `json:"current_period_start"`
	CurrentPeriodEnd    string          `json:"current_period_end"`
}

func (h *AccountHandler) HandleGetUsage(w http.ResponseWriter, r *http.Request) {
	subID, ok := r.Context().Value(subscriberKey).(string)
	if !ok || subID == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	var tokensIssued, bandwidth int64
	var periodStart, periodEnd time.Time
	if err := h.pool.QueryRow(r.Context(),
		`SELECT tokens_issued, bandwidth_used, current_period_start, current_period_end
		 FROM subscriptions
		 WHERE subscriber_id = $1
		 ORDER BY created_at DESC LIMIT 1`, subID,
	).Scan(&tokensIssued, &bandwidth, &periodStart, &periodEnd); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}

	var circuits int64
	if err := h.pool.QueryRow(r.Context(),
		`SELECT COUNT(*) FROM circuit_assignments
		 WHERE subscriber_id = $1 AND created_at >= $2`,
		subID, periodStart,
	).Scan(&circuits); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}

	rows, err := h.pool.Query(r.Context(),
		`SELECT role, COUNT(*) FROM relay_nodes
		 WHERE status = 'active'
		 GROUP BY role`,
	)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	defer rows.Close()
	counts := relayRoleCounts{}
	for rows.Next() {
		var role string
		var n int
		if err := rows.Scan(&role, &n); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
			return
		}
		switch role {
		case "guard":
			counts.Guard = n
		case "middle":
			counts.Middle = n
		case "exit":
			counts.Exit = n
		}
	}
	if err := rows.Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}

	writeJSON(w, http.StatusOK, usageResponse{
		TokensIssued:       tokensIssued,
		BandwidthUsed:      bandwidth,
		CircuitsAssigned:   circuits,
		ActiveRelays:       counts,
		CurrentPeriodStart: periodStart.UTC().Format(time.RFC3339),
		CurrentPeriodEnd:   periodEnd.UTC().Format(time.RFC3339),
	})
}
