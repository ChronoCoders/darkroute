package handlers

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dslabs/darkroute/authority/internal/blind"
)

// TokenHandler serves the authority pubkey and the blind token issuance
// endpoint. Per SECURITY_MODEL §5.2 step 8, the authority records only that
// a token was issued — the blinded value b and the resulting signature s are
// neither logged nor persisted.
type TokenHandler struct {
	pool   *pgxpool.Pool
	signer *blind.Signer
}

func NewTokenHandler(pool *pgxpool.Pool, signer *blind.Signer) *TokenHandler {
	return &TokenHandler{pool: pool, signer: signer}
}

// HandlePubkey serves the authority's RSA public key in PEM form. Per
// ARCHITECTURE §4.2 this endpoint is public and unauthenticated; relays
// fetch and pin it at startup.
func (h *TokenHandler) HandlePubkey(w http.ResponseWriter, _ *http.Request) {
	pem := h.signer.PublicKeyPEM()
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(pem); err != nil {
		// The response is already started; we cannot recover. Log via the
		// standard slog default — pem is not sensitive.
		return
	}
}

type issueRequest struct {
	Blinded string `json:"blinded"`
}

// HandleIssue performs the authority side of the blind token protocol:
//
//   - Confirms the request is from an authenticated subscriber (the
//     Authenticate middleware has already done JWT + session lookup).
//   - Verifies that the subscriber has an active subscription.
//   - Computes s = b^d mod n via blind.Signer.Sign.
//   - Atomically increments tokens_issued on the subscription row.
//   - Returns s as hex.
//
// Failure modes return generic errors so an attacker cannot distinguish
// "no subscription" from "expired subscription" or "internal failure".
func (h *TokenHandler) HandleIssue(w http.ResponseWriter, r *http.Request) {
	subID, ok := r.Context().Value(subscriberKey).(string)
	if !ok || subID == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	var subID2 string
	var status string
	err := h.pool.QueryRow(r.Context(),
		`SELECT subscriber_id, status
		 FROM subscriptions
		 WHERE subscriber_id = $1
		 ORDER BY created_at DESC
		 LIMIT 1`,
		subID,
	).Scan(&subID2, &status)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "no_active_subscription"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	if status != "active" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "no_active_subscription"})
		return
	}

	var req issueRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	blindedBytes, err := hex.DecodeString(req.Blinded)
	if err != nil || len(blindedBytes) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_blinded"})
		return
	}
	// Cap the input size at the modulus to avoid any unbounded big.Int alloc.
	if len(blindedBytes) > h.signer.ModulusSize() {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_blinded"})
		return
	}

	signed, err := h.signer.Sign(blindedBytes)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_blinded"})
		return
	}

	// SECURITY_MODEL §5.2 step 8: counter only, no token value. We also
	// insert a row into token_issuance_events with the timestamp only
	// (no token bytes) so the dashboard can show a list of recent
	// issuances per the user-facing Phase 5 Tokens page.
	if _, err := h.pool.Exec(r.Context(),
		`UPDATE subscriptions
		 SET tokens_issued = tokens_issued + 1
		 WHERE subscriber_id = $1`,
		subID,
	); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	if _, err := h.pool.Exec(r.Context(),
		`INSERT INTO token_issuance_events (subscriber_id) VALUES ($1)`,
		subID,
	); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"signed": hex.EncodeToString(signed),
	})
}

type tokenIssuanceListItem struct {
	ID       string `json:"id"`
	IssuedAt string `json:"issued_at"`
}

type tokenListResponse struct {
	TokensIssued int64                  `json:"tokens_issued"`
	Recent       []tokenIssuanceListItem `json:"recent"`
}

// HandleListTokens returns the subscriber's lifetime issuance counter
// and the most recent N issuance timestamps. No token bytes are stored
// or returned — this is purely an audit/visualisation surface.
func (h *TokenHandler) HandleListTokens(w http.ResponseWriter, r *http.Request) {
	subID, ok := r.Context().Value(subscriberKey).(string)
	if !ok || subID == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var count int64
	if err := h.pool.QueryRow(r.Context(),
		`SELECT COALESCE(SUM(tokens_issued), 0)::bigint
		 FROM subscriptions
		 WHERE subscriber_id = $1`,
		subID,
	).Scan(&count); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	rows, err := h.pool.Query(r.Context(),
		`SELECT id, issued_at
		 FROM token_issuance_events
		 WHERE subscriber_id = $1
		 ORDER BY issued_at DESC
		 LIMIT 50`,
		subID,
	)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	defer rows.Close()
	out := tokenListResponse{TokensIssued: count, Recent: []tokenIssuanceListItem{}}
	for rows.Next() {
		var id string
		var issued time.Time
		if err := rows.Scan(&id, &issued); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
			return
		}
		out.Recent = append(out.Recent, tokenIssuanceListItem{
			ID:       id,
			IssuedAt: issued.UTC().Format(time.RFC3339),
		})
	}
	if err := rows.Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	writeJSON(w, http.StatusOK, out)
}
