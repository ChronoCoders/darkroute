package handlers

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeNoDB is used to prove the IP check happens before any DB access. If the
// handler ever reaches RecordHeartbeat with allowedIPs empty, the test will
// fail with a nil-pointer panic instead of returning a clean 401.
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
	// No Authorization header
	rec := httptest.NewRecorder()

	h.HandleRelayHeartbeat(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d want 401", rec.Code)
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
