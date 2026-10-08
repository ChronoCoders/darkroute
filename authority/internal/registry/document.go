package registry

import "time"

// FreshWindow is how long a document is the newest expected publication.
// ValidWindow is how long a client may still use it. A client refuses anything
// past valid_until with no grace period (SECURITY_MODEL 5.3).
const (
	FreshWindow = 1 * time.Hour
	ValidWindow = 6 * time.Hour
)

// RelayEntry is one relay as published. Field order here is the field order in
// the signed bytes, because encoding/json follows struct declaration order.
//
// ip is a literal and never a name: nothing in path construction resolves one
// (SECURITY_MODEL 5.3). tls_name is for SNI and certificate verification only.
type RelayEntry struct {
	ID           string `json:"id"`
	OperatorID   string `json:"operator_id"`
	HostID       string `json:"host_id"`
	Role         string `json:"role"`
	IP           string `json:"ip"`
	Port         int    `json:"port"`
	TLSName      string `json:"tls_name"`
	StaticPubkey string `json:"static_pubkey"`
}

// Document is the signed registry. Times are RFC 3339 UTC with a Z suffix.
type Document struct {
	Version    int64        `json:"version"`
	ValidAfter string       `json:"valid_after"`
	FreshUntil string       `json:"fresh_until"`
	ValidUntil string       `json:"valid_until"`
	Relays     []RelayEntry `json:"relays"`
}

// HourOf truncates to the publication boundary. Every client fetching within
// one hour must get the same bytes, so the hour is the document's identity.
func HourOf(t time.Time) time.Time {
	return t.UTC().Truncate(time.Hour)
}

func stamp(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}
