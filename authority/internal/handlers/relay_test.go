package handlers

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The IP check must happen before any DB access. If the handler ever
// reaches RecordHeartbeat with allowedIPs empty, the test will fail with
// a nil-pointer panic instead of returning a clean 401.
func TestHeartbeatRejectsUnlistedIPBeforeAPIKeyCheck(t *testing.T) {
	h := NewRelayHandler(nil, "salt-x", nil) // allowedIPs empty
	req := httptest.NewRequest(http.MethodPost, "/api/v1/relay/heartbeat", nil)
	req.RemoteAddr = "203.0.113.5:55000"
	req.Header.Set("Authorization", "Bearer would-be-valid-key")
	rec := httptest.NewRecorder()

	h.HandleRelayHeartbeat(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d want 401", rec.Code)
	}
}

func TestHeartbeatRejectsXForwardedForSpoofing(t *testing.T) {
	// Even with the trusted IP in X-Forwarded-For, the handler must look only
	// at the TCP peer address. Otherwise an attacker behind a misconfigured
	// proxy could bypass the allowlist by setting the header.
	h := NewRelayHandler(nil, "salt-x", []string{"10.0.0.5"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/relay/heartbeat", bytes.NewReader(nil))
	req.RemoteAddr = "203.0.113.5:55000"
	req.Header.Set("X-Forwarded-For", "10.0.0.5")
	req.Header.Set("Authorization", "Bearer anything")
	rec := httptest.NewRecorder()

	h.HandleRelayHeartbeat(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("XFF spoof was not rejected; got %d", rec.Code)
	}
}

func TestHeartbeatRejectsMissingAuthorizationHeader(t *testing.T) {
	h := NewRelayHandler(nil, "salt-x", []string{"10.0.0.5"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/relay/heartbeat", nil)
	req.RemoteAddr = "10.0.0.5:55000"
	rec := httptest.NewRecorder()

	h.HandleRelayHeartbeat(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d want 401", rec.Code)
	}
}

func TestPeerIPTrustsCFConnectingIPFromLoopback(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.RemoteAddr = "127.0.0.1:55000"
	req.Header.Set("CF-Connecting-IP", "203.0.113.7")
	if got := peerIP(req); got != "203.0.113.7" {
		t.Fatalf("loopback + CF header: got %q want 203.0.113.7", got)
	}
}

func TestPeerIPIgnoresCFConnectingIPFromNonLoopback(t *testing.T) {
	// CF-Connecting-IP from a non-loopback peer is client-controllable
	// and must not be honored. Otherwise the rate limiter and the
	// heartbeat allowlist would be bypassable by anyone who can reach
	// the authority directly (i.e., everyone, before Cloudflare is in
	// front).
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.RemoteAddr = "203.0.113.5:55000"
	req.Header.Set("CF-Connecting-IP", "10.0.0.5")
	if got := peerIP(req); got != "203.0.113.5" {
		t.Fatalf("non-loopback peer with CF header: got %q want 203.0.113.5", got)
	}
}

func TestPeerIPFallsBackToTCPPeerWhenNoCFHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.RemoteAddr = "127.0.0.1:55000"
	if got := peerIP(req); got != "127.0.0.1" {
		t.Fatalf("loopback no CF header: got %q want 127.0.0.1", got)
	}
}

func TestHeartbeatRejectsNonBearerAuthorization(t *testing.T) {
	h := NewRelayHandler(nil, "salt-x", []string{"10.0.0.5"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/relay/heartbeat", nil)
	req.RemoteAddr = "10.0.0.5:55000"
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rec := httptest.NewRecorder()

	h.HandleRelayHeartbeat(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d want 401", rec.Code)
	}
}
