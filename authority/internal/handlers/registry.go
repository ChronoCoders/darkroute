package handlers

import (
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/ChronoCoders/quiethop/authority/internal/registry"
)

// RegistryHandler serves the signed relay registry.
//
// The endpoint is public and unauthenticated. Its integrity rests on the
// Ed25519 signature, not on the transport or on a session
// (SECURITY_MODEL 7.3), and requiring a session would tell the authority which
// subscriber was about to build a circuit.
type RegistryHandler struct {
	pub *registry.Publisher
}

func NewRegistryHandler(pub *registry.Publisher) *RegistryHandler {
	return &RegistryHandler{pub: pub}
}

func (h *RegistryHandler) HandleRegistry(w http.ResponseWriter, r *http.Request) {
	doc, sigs, err := h.pub.Current(r.Context(), time.Now())
	if err != nil {
		if errors.Is(err, registry.ErrNoDocument) {
			// No stored document and none can be built. Returning an
			// unsigned or expired document would be worse than failing.
			slog.Error("registry unavailable", "err", err)
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "unavailable"})
			return
		}
		slog.Error("registry build failed", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	writeJSON(w, http.StatusOK, registry.Response{
		Document:   base64Std(doc),
		Signatures: sigs,
	})
}

func base64Std(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
