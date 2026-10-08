package relay

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrInvalidRole       = errors.New("invalid relay role")
	ErrUnknownRelay      = errors.New("unknown relay")
	ErrInvalidStaticKey  = errors.New("static public key is not 32 bytes")
	ErrMissingIdentifier = errors.New("operator_id and host_id are required")
	ErrInvalidAddress    = errors.New("invalid relay address")
	ErrStaticKeyMismatch = errors.New("static public key does not match the provisioned one")
)

// StaticKeyLen is the X25519 public key length. The database enforces the same
// bound with a CHECK constraint, so a direct insert cannot bypass it.
const StaticKeyLen = 32

type Relay struct {
	ID            string     `json:"id"`
	TLSName       string     `json:"tls_name"`
	IP            string     `json:"ip"`
	Port          int        `json:"port"`
	Region        string     `json:"region"`
	Role          string     `json:"role"`
	Status        string     `json:"status"`
	OperatorID    string     `json:"operator_id"`
	HostID        string     `json:"host_id"`
	LastHeartbeat *time.Time `json:"last_heartbeat,omitempty"`
	// StaticPubkey is raw bytes in Go and hex on the wire. Handlers encode it;
	// it is public key material, so it carries no disclosure risk.
	StaticPubkey []byte `json:"-"`
}

// StaticPubkeyHex renders the key for a JSON response.
func (r *Relay) StaticPubkeyHex() string {
	return hex.EncodeToString(r.StaticPubkey)
}

const relayColumns = `id, tls_name, host(ip), port, region, role, status, operator_id, host_id, last_heartbeat, static_pubkey`

func scanRelay(row pgx.Row, r *Relay) error {
	return row.Scan(&r.ID, &r.TLSName, &r.IP, &r.Port, &r.Region, &r.Role, &r.Status, &r.OperatorID, &r.HostID, &r.LastHeartbeat, &r.StaticPubkey)
}

// ValidateStaticKey rejects anything that is not exactly an X25519 public key.
func ValidateStaticKey(key []byte) error {
	if len(key) != StaticKeyLen {
		return ErrInvalidStaticKey
	}
	return nil
}

func validRole(role string) bool {
	switch role {
	case "guard", "middle", "exit":
		return true
	}
	return false
}

// SECURITY_MODEL §7.2 specifies SHA-256; the salt from RELAY_API_KEY_SALT
// is included so a database dump alone does not enable offline brute-force
// against short or low-entropy keys.
func hashAPIKey(salt, plaintext string) string {
	h := sha256.New()
	h.Write([]byte(salt))
	h.Write([]byte(plaintext))
	return hex.EncodeToString(h.Sum(nil))
}

func generateAPIKey() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// The plaintext key is returned to the caller exactly once and never
// persisted; only its salted SHA-256 hash is stored.
func ProvisionRelay(ctx context.Context, pool *pgxpool.Pool, salt, tlsName, region, role, ip string, port int, staticPubkey []byte, operatorID, hostID string) (string, string, error) {
	if !validRole(role) {
		return "", "", ErrInvalidRole
	}
	// Both identifiers are assigned here and never by the relay. A relay
	// without them cannot appear in a registry a client can check
	// (ARCHITECTURE 4.7).
	if operatorID == "" || hostID == "" {
		return "", "", ErrMissingIdentifier
	}
	if err := ValidateStaticKey(staticPubkey); err != nil {
		return "", "", err
	}
	if _, err := netip.ParseAddr(ip); err != nil {
		return "", "", ErrInvalidAddress
	}
	if port < 1 || port > 65535 {
		return "", "", ErrInvalidAddress
	}
	plaintext, err := generateAPIKey()
	if err != nil {
		return "", "", err
	}
	hash := hashAPIKey(salt, plaintext)
	var id string
	err = pool.QueryRow(ctx,
		`INSERT INTO relay_nodes (id, api_key_hash, tls_name, region, role, status, ip, port, static_pubkey, operator_id, host_id)
		 VALUES (gen_random_uuid(), $1, $2, $3, $4, 'inactive', $5, $6, $7, $8, $9)
		 RETURNING id`,
		hash, tlsName, region, role, ip, port, staticPubkey, operatorID, hostID,
	).Scan(&id)
	if err != nil {
		return "", "", err
	}
	return id, plaintext, nil
}

// RecordHeartbeat marks a relay active. The static public key is written only
// at provisioning time and is immutable (SECURITY_MODEL 7.2). A heartbeat may
// carry the key; if it differs from the stored one the heartbeat is rejected
// and nothing is updated. offered may be nil, which skips the comparison.
//
// The comparison and the update are one statement so that a heartbeat cannot
// be admitted on the strength of a key read a moment earlier.
func RecordHeartbeat(ctx context.Context, pool *pgxpool.Pool, salt, plaintext string, offered []byte) (string, error) {
	if offered != nil {
		if err := ValidateStaticKey(offered); err != nil {
			return "", err
		}
	}
	hash := hashAPIKey(salt, plaintext)
	var id string
	err := pool.QueryRow(ctx,
		`UPDATE relay_nodes
		 SET status = 'active', last_heartbeat = NOW()
		 WHERE api_key_hash = $1
		   AND ($2::bytea IS NULL OR static_pubkey = $2)
		 RETURNING id`,
		hash, offered,
	).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	// No row changed. Separate an unknown relay from a key mismatch so the
	// caller can log the relay id. This read cannot re-admit the heartbeat.
	var knownID string
	var stored []byte
	lookupErr := pool.QueryRow(ctx,
		`SELECT id, static_pubkey FROM relay_nodes WHERE api_key_hash = $1`, hash,
	).Scan(&knownID, &stored)
	if lookupErr != nil {
		return "", ErrUnknownRelay
	}
	if offered != nil && !bytes.Equal(offered, stored) {
		return knownID, ErrStaticKeyMismatch
	}
	return "", ErrUnknownRelay
}

func scanRelays(ctx context.Context, pool *pgxpool.Pool, sql string, args ...any) ([]Relay, error) {
	rows, err := pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Relay
	for rows.Next() {
		var r Relay
		if err := scanRelay(rows, &r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func GetActiveRelays(ctx context.Context, pool *pgxpool.Pool) ([]Relay, error) {
	return scanRelays(ctx, pool,
		`SELECT `+relayColumns+`
		 FROM relay_nodes
		 WHERE status = 'active'
		 ORDER BY created_at`)
}

// PickRandomActiveByRole returns one active relay with the requested role,
// chosen uniformly at random from the eligible pool. Any relay whose ID is
// in excludeIDs is filtered out, so the circuit-route handler can require
// three distinct physical nodes across guard/middle/exit. This is mandatory
// per SECURITY_MODEL §9: the same host serving both guard and exit would
// collapse the unlinkability between client IP (guard's view) and
// destination (exit's view).
//
// Returns pgx.ErrNoRows when no active relay of the requested role exists
// outside the excluded set; callers map that to a 503.
func PickRandomActiveByRole(ctx context.Context, pool *pgxpool.Pool, role string, excludeIDs ...string) (*Relay, error) {
	if !validRole(role) {
		return nil, ErrInvalidRole
	}
	// pgx serializes nil slices as SQL NULL; `ANY(NULL)` evaluates to NULL
	// and the WHERE clause drops the row, so a no-exclusions call would
	// never match. Force the empty-array case so the picker can pick on
	// the first hop of a circuit.
	if excludeIDs == nil {
		excludeIDs = []string{}
	}
	r := &Relay{}
	row := pool.QueryRow(ctx,
		`SELECT `+relayColumns+`
		 FROM relay_nodes
		 WHERE role = $1
		   AND status = 'active'
		   AND NOT (id = ANY($2::uuid[]))
		 ORDER BY random()
		 LIMIT 1`,
		role, excludeIDs,
	)
	if err := scanRelay(row, r); err != nil {
		return nil, err
	}
	return r, nil
}

func SweepInactiveRelays(ctx context.Context, pool *pgxpool.Pool, ttl time.Duration) (int64, error) {
	seconds := int64(ttl.Seconds())
	if seconds < 1 {
		seconds = 1
	}
	tag, err := pool.Exec(ctx,
		`UPDATE relay_nodes
		 SET status = 'inactive'
		 WHERE status = 'active'
		   AND (last_heartbeat IS NULL OR last_heartbeat < NOW() - make_interval(secs => $1))`,
		seconds,
	)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
