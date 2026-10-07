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

// A relay whose key file differs from the key recorded at provisioning time
// must be rejected over HTTP with 409 and must not be marked active. This is
// the contract the relay's heartbeat task depends on: it sends the public half
// of whatever key file it loaded, and a mismatch means an operator has to
// re-provision or restore the original file.
func TestHeartbeatHTTPRejectsMismatchedStaticKey(t *testing.T) {
	pool := testPool(t)
	h := NewRelayHandler(pool, "salt-pin-http", []string{"127.0.0.1"})

	provisioned := make([]byte, 32)
	for i := range provisioned {
		provisioned[i] = 0x11
	}
	id, apiKey := provisionForTest(t, pool, "salt-pin-http", provisioned)

	post := func(keyHex string) *httptest.ResponseRecorder {
		body := bytes.NewBufferString(`{"static_pubkey":"` + keyHex + `"}`)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/relay/heartbeat", body)
		req.RemoteAddr = "127.0.0.1:55000"
		req.Header.Set("Authorization", "Bearer "+apiKey)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.HandleRelayHeartbeat(rec, req)
		return rec
	}

	// Control: the provisioned key is accepted and the relay goes active.
	if rec := post(hexOf(provisioned)); rec.Code != http.StatusNoContent {
		t.Fatalf("matching key: status got %d want 204, body=%s", rec.Code, rec.Body.String())
	}
	if got := relayStatusByID(t, pool, id); got != "active" {
		t.Fatalf("after a matching heartbeat status = %q, want active", got)
	}

	// Park it inactive so a rejected heartbeat has something to fail to change.
	if _, err := pool.Exec(reqCtx(), `UPDATE relay_nodes SET status='inactive' WHERE id=$1`, id); err != nil {
		t.Fatalf("park inactive: %v", err)
	}

	// A different key: 409, nothing updated.
	wrong := make([]byte, 32)
	copy(wrong, provisioned)
	wrong[0] ^= 0xFF
	rec := post(hexOf(wrong))
	if rec.Code != http.StatusConflict {
		t.Fatalf("mismatched key: status got %d want 409, body=%s", rec.Code, rec.Body.String())
	}
	if got := relayStatusByID(t, pool, id); got != "inactive" {
		t.Errorf("a rejected heartbeat marked the relay %q, want it left inactive", got)
	}
}
