package relay

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrInvalidRole  = errors.New("invalid relay role")
	ErrUnknownRelay = errors.New("unknown relay")
)

type Relay struct {
	ID            string     `json:"id"`
	Endpoint      string     `json:"endpoint"`
	Region        string     `json:"region"`
	Role          string     `json:"role"`
	Status        string     `json:"status"`
	LastHeartbeat *time.Time `json:"last_heartbeat,omitempty"`
}

func validRole(role string) bool {
	switch role {
	case "guard", "middle", "exit":
		return true
	}
	return false
}

// hashAPIKey computes SHA-256(salt || plaintext). The spec (SECURITY_MODEL §7.2)
// specifies SHA-256; the salt from RELAY_API_KEY_SALT is included so a database
// dump alone does not enable offline brute-force against short or low-entropy keys.
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

// ProvisionRelay inserts a new relay row and returns the plaintext API key
// to the caller. The plaintext key is never persisted; only its salted SHA-256
// hash is stored.
func ProvisionRelay(ctx context.Context, pool *pgxpool.Pool, salt, endpoint, region, role string) (string, string, error) {
	if !validRole(role) {
		return "", "", ErrInvalidRole
	}
	plaintext, err := generateAPIKey()
	if err != nil {
		return "", "", err
	}
	hash := hashAPIKey(salt, plaintext)
	var id string
	err = pool.QueryRow(ctx,
		`INSERT INTO relay_nodes (id, api_key_hash, endpoint, region, role, status)
		 VALUES (gen_random_uuid(), $1, $2, $3, $4, 'inactive')
		 RETURNING id`,
		hash, endpoint, region, role,
	).Scan(&id)
	if err != nil {
		return "", "", err
	}
	return id, plaintext, nil
}

func RecordHeartbeat(ctx context.Context, pool *pgxpool.Pool, salt, plaintext string) (string, error) {
	hash := hashAPIKey(salt, plaintext)
	var id string
	err := pool.QueryRow(ctx,
		`UPDATE relay_nodes
		 SET status = 'active', last_heartbeat = NOW()
		 WHERE api_key_hash = $1
		 RETURNING id`,
		hash,
	).Scan(&id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrUnknownRelay
		}
		return "", err
	}
	return id, nil
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
		if err := rows.Scan(&r.ID, &r.Endpoint, &r.Region, &r.Role, &r.Status, &r.LastHeartbeat); err != nil {
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
		`SELECT id, endpoint, region, role, status, last_heartbeat
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
	r := &Relay{}
	err := pool.QueryRow(ctx,
		`SELECT id, endpoint, region, role, status, last_heartbeat
		 FROM relay_nodes
		 WHERE role = $1
		   AND status = 'active'
		   AND NOT (id = ANY($2::uuid[]))
		 ORDER BY random()
		 LIMIT 1`,
		role, excludeIDs,
	).Scan(&r.ID, &r.Endpoint, &r.Region, &r.Role, &r.Status, &r.LastHeartbeat)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// SweepInactiveRelays marks any active relay as inactive when its last heartbeat
// is older than ttl (or absent). Returns the number of rows affected.
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
