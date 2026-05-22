package handlers

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AdminHandler serves the admin-tier surfaces: subscriber listing and
// the pending-review approval action. All routes are mounted behind
// RequireRole("admin") in main.go; this handler does not re-check the
// role itself.
type AdminHandler struct {
	pool *pgxpool.Pool
}

func NewAdminHandler(pool *pgxpool.Pool) *AdminHandler {
	return &AdminHandler{pool: pool}
}

type adminSubscriberItem struct {
	ID                 string `json:"id"`
	Email              string `json:"email"`
	Role               string `json:"role"`
	SubscriberCreated  string `json:"subscriber_created_at"`
	Tier               string `json:"tier"`
	Status             string `json:"status"`
	TokensIssued       int64  `json:"tokens_issued"`
	BandwidthUsed      int64  `json:"bandwidth_used"`
	CurrentPeriodStart string `json:"current_period_start"`
	CurrentPeriodEnd   string `json:"current_period_end"`
}

type adminSubscribersResponse struct {
	Subscribers []adminSubscriberItem `json:"subscribers"`
}

func (h *AdminHandler) HandleListSubscribers(w http.ResponseWriter, r *http.Request) {
	rows, err := h.pool.Query(r.Context(),
		`SELECT s.id, s.email, s.role, s.created_at,
		        sub.tier, sub.status, sub.tokens_issued, sub.bandwidth_used,
		        sub.current_period_start, sub.current_period_end
		 FROM subscribers s
		 LEFT JOIN LATERAL (
		     SELECT tier, status, tokens_issued, bandwidth_used,
		            current_period_start, current_period_end
		     FROM subscriptions
		     WHERE subscriber_id = s.id
		     ORDER BY created_at DESC LIMIT 1
		 ) sub ON true
		 ORDER BY s.created_at DESC`,
	)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	defer rows.Close()
	out := adminSubscribersResponse{Subscribers: []adminSubscriberItem{}}
	for rows.Next() {
		var item adminSubscriberItem
		var subCreated time.Time
		var tier, status *string
		var tokensIssued, bandwidth *int64
		var periodStart, periodEnd *time.Time
		if err := rows.Scan(
			&item.ID, &item.Email, &item.Role, &subCreated,
			&tier, &status, &tokensIssued, &bandwidth,
			&periodStart, &periodEnd,
		); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
			return
		}
		item.SubscriberCreated = subCreated.UTC().Format(time.RFC3339)
		if tier != nil {
			item.Tier = *tier
		}
		if status != nil {
			item.Status = *status
		}
		if tokensIssued != nil {
			item.TokensIssued = *tokensIssued
		}
		if bandwidth != nil {
			item.BandwidthUsed = *bandwidth
		}
		if periodStart != nil {
			item.CurrentPeriodStart = periodStart.UTC().Format(time.RFC3339)
		}
		if periodEnd != nil {
			item.CurrentPeriodEnd = periodEnd.UTC().Format(time.RFC3339)
		}
		out.Subscribers = append(out.Subscribers, item)
	}
	if err := rows.Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// HandleApproveSubscriber flips a subscriber's latest subscription
// from pending_review (or any non-active state) to active. The
// onboarding gate the dashboard surfaces (Account: "pending review")
// is released by this action and only this action.
func (h *AdminHandler) HandleApproveSubscriber(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing_id"})
		return
	}
	var subID string
	err := h.pool.QueryRow(r.Context(),
		`UPDATE subscriptions
		 SET status = 'active'
		 WHERE subscriber_id = $1
		   AND created_at = (
		       SELECT MAX(created_at) FROM subscriptions WHERE subscriber_id = $1
		   )
		 RETURNING subscriber_id`,
		id,
	).Scan(&subID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": subID, "status": "active"})
}
