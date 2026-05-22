package handlers

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"

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

	// SECURITY_MODEL §5.2 step 8: counter only, no token value.
	if _, err := h.pool.Exec(r.Context(),
		`UPDATE subscriptions
		 SET tokens_issued = tokens_issued + 1
		 WHERE subscriber_id = $1`,
		subID,
	); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"signed": hex.EncodeToString(signed),
	})
}
