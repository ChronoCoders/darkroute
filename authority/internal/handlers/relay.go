package handlers

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ChronoCoders/quiethop/authority/internal/relay"
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
// loopback, so when the TCP peer is loopback we trust CF-Connecting-IP,
// and only then. Any other peer is the legacy direct-listen path and
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

	// The body is optional. When it carries a static public key the authority
	// compares it with the provisioned one and rejects a mismatch without
	// updating anything (SECURITY_MODEL 7.2).
	var offered []byte
	var body heartbeatRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err == nil && body.StaticPubkey != "" {
		decoded, decodeErr := hex.DecodeString(body.StaticPubkey)
		if decodeErr != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_static_pubkey"})
			return
		}
		offered = decoded
	}

	id, err := relay.RecordHeartbeat(r.Context(), h.pool, h.salt, key, offered)
	if err != nil {
		if errors.Is(err, relay.ErrStaticKeyMismatch) {
			// The relay id identifies which node to investigate. The key
			// bytes are deliberately not logged.
			slog.Warn("relay heartbeat rejected: static public key does not match the provisioned one", "relay_id", id)
			writeJSON(w, http.StatusConflict, map[string]string{"error": "static_pubkey_mismatch"})
			return
		}
		// Same response for unknown relay and infrastructure failures.
		// Do not leak which check failed.
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type heartbeatRequest struct {
	StaticPubkey string `json:"static_pubkey"`
}

type provisionRelayRequest struct {
	TLSName      string `json:"tls_name"`
	IP           string `json:"ip"`
	Port         int    `json:"port"`
	Region       string `json:"region"`
	Role         string `json:"role"`
	StaticPubkey string `json:"static_pubkey"`
}

func (h *RelayHandler) HandleProvisionRelay(w http.ResponseWriter, r *http.Request) {
	var req provisionRelayRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	if req.TLSName == "" || req.Region == "" || req.IP == "" || req.StaticPubkey == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing_fields"})
		return
	}
	pubkey, err := hex.DecodeString(req.StaticPubkey)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_static_pubkey"})
		return
	}
	id, plaintext, err := relay.ProvisionRelay(r.Context(), h.pool, h.salt, req.TLSName, req.Region, req.Role, req.IP, req.Port, pubkey)
	if err != nil {
		switch {
		case errors.Is(err, relay.ErrInvalidRole):
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_role"})
		case errors.Is(err, relay.ErrInvalidStaticKey):
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_static_pubkey"})
		case errors.Is(err, relay.ErrInvalidAddress):
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_address"})
		default:
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		}
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
	// relay.Relay carries no api_key_hash: the field is unexported from the
	// query, so the JSON response cannot leak it.
	writeJSON(w, http.StatusOK, map[string]any{"relays": relays})
}
