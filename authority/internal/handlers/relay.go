package handlers

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dslabs/darkroute/authority/internal/relay"
)

type RelayHandler struct {
	pool       *pgxpool.Pool
	salt       string
	allowedIPs map[string]struct{}
}

func NewRelayHandler(pool *pgxpool.Pool, salt string, allowedIPs []string) *RelayHandler {
	set := make(map[string]struct{}, len(allowedIPs))
	for _, ip := range allowedIPs {
		trimmed := strings.TrimSpace(ip)
		if trimmed != "" {
			set[trimmed] = struct{}{}
		}
	}
	return &RelayHandler{pool: pool, salt: salt, allowedIPs: set}
}

// peerIP returns the real caller IP. Cloudflare Tunnel terminates on
// loopback, so when the TCP peer is loopback we trust CF-Connecting-IP
// — and only then. Any other peer is the legacy direct-listen path and
// the header is ignored as client-controllable.
func peerIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if host == "127.0.0.1" || host == "::1" {
		if cf := r.Header.Get("CF-Connecting-IP"); cf != "" {
			return cf
		}
	}
	return host
}

func (h *RelayHandler) HandleRelayHeartbeat(w http.ResponseWriter, r *http.Request) {
	// IP allowlist first, per SECURITY_MODEL.md §7.2: source IP check runs
	// BEFORE API key validation, and both must pass.
	if _, ok := h.allowedIPs[peerIP(r)]; !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	key := strings.TrimPrefix(authHeader, "Bearer ")
	if _, err := relay.RecordHeartbeat(r.Context(), h.pool, h.salt, key); err != nil {
		// Same response for unknown relay and infrastructure failures —
		// do not leak which check failed.
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type provisionRelayRequest struct {
	Endpoint string `json:"endpoint"`
	Region   string `json:"region"`
	Role     string `json:"role"`
}

func (h *RelayHandler) HandleProvisionRelay(w http.ResponseWriter, r *http.Request) {
	var req provisionRelayRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	if req.Endpoint == "" || req.Region == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing_fields"})
		return
	}
	id, plaintext, err := relay.ProvisionRelay(r.Context(), h.pool, h.salt, req.Endpoint, req.Region, req.Role)
	if err != nil {
		if errors.Is(err, relay.ErrInvalidRole) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_role"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	// Plaintext API key is returned exactly once. The hash-only store ensures
	// it cannot be recovered later (SECURITY_MODEL §7.2).
	writeJSON(w, http.StatusCreated, map[string]string{
		"id":      id,
		"api_key": plaintext,
	})
}

func (h *RelayHandler) HandleListRelays(w http.ResponseWriter, r *http.Request) {
	relays, err := relay.GetActiveRelays(r.Context(), h.pool)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	// relay.Relay carries no api_key_hash — the field is unexported from the
	// query, so the JSON response cannot leak it.
	writeJSON(w, http.StatusOK, map[string]any{"relays": relays})
}
