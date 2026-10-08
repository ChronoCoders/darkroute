package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNoDocument means no document is available and none can be built, so the
// endpoint must fail rather than serve something unsigned or stale past its
// validity.
var ErrNoDocument = errors.New("no registry document available")

// Publisher serves the current hour's document, building and storing one when
// the hour has no row yet.
//
// Storage is the database, not memory. The in-memory copy exists only to answer
// while the database is unreachable, and only until that document's
// valid_until passes.
type Publisher struct {
	pool   *pgxpool.Pool
	signer *Signer

	mu       sync.RWMutex
	lastDoc  []byte
	lastSigs []Signature
	lastTil  time.Time
}

func NewPublisher(pool *pgxpool.Pool, signer *Signer) *Publisher {
	return &Publisher{pool: pool, signer: signer}
}

// Current returns the document and signatures for the hour containing now.
//
// It never returns bytes that were not stored: a freshly built document is
// served only after its INSERT succeeded, and a losing INSERT re-reads the
// winner's row instead of serving what it just built.
func (p *Publisher) Current(ctx context.Context, now time.Time) ([]byte, []Signature, error) {
	hour := HourOf(now)

	doc, sigs, err := p.load(ctx, hour)
	if err == nil {
		p.remember(doc, sigs, hour.Add(ValidWindow))
		return doc, sigs, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		// The database is unreachable or failing. Serve the last stored
		// document while it is still valid, and otherwise fail. Never sign
		// a document built from a query that did not complete.
		if doc, sigs, ok := p.cached(now); ok {
			return doc, sigs, nil
		}
		return nil, nil, fmt.Errorf("%w: %v", ErrNoDocument, err)
	}

	built, sigs, err := p.publish(ctx, hour)
	if err != nil {
		if doc, sigs, ok := p.cached(now); ok {
			return doc, sigs, nil
		}
		return nil, nil, err
	}
	p.remember(built, sigs, hour.Add(ValidWindow))
	return built, sigs, nil
}

// publish builds, signs and stores the document for one hour. On a unique
// conflict another instance or request won the race, and its row is served.
func (p *Publisher) publish(ctx context.Context, hour time.Time) ([]byte, []Signature, error) {
	relays, err := p.activeRelays(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("read active relays: %w", err)
	}

	var next int64
	if err := p.pool.QueryRow(ctx,
		`SELECT COALESCE(MAX(version), 0) + 1 FROM registry_documents`).Scan(&next); err != nil {
		return nil, nil, fmt.Errorf("next version: %w", err)
	}

	doc := Document{
		Version:    next,
		ValidAfter: stamp(hour),
		FreshUntil: stamp(hour.Add(FreshWindow)),
		ValidUntil: stamp(hour.Add(ValidWindow)),
		Relays:     relays,
	}
	bytes, err := json.Marshal(doc)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal document: %w", err)
	}
	sigs := []Signature{p.signer.Sign(bytes)}
	sigsJSON, err := MarshalSignatures(sigs)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal signatures: %w", err)
	}

	tag, err := p.pool.Exec(ctx,
		`INSERT INTO registry_documents (version, valid_after, document, signatures)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT DO NOTHING`,
		next, hour, bytes, sigsJSON,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("insert document: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return bytes, sigs, nil
	}

	// Lost the race. Discard what was just built and serve the stored winner,
	// so two clients in the same hour cannot see different bytes.
	return p.load(ctx, hour)
}

func (p *Publisher) load(ctx context.Context, hour time.Time) ([]byte, []Signature, error) {
	var doc []byte
	var sigsRaw []byte
	err := p.pool.QueryRow(ctx,
		`SELECT document, signatures FROM registry_documents WHERE valid_after = $1`,
		hour,
	).Scan(&doc, &sigsRaw)
	if err != nil {
		return nil, nil, err
	}
	sigs, err := UnmarshalSignatures(sigsRaw)
	if err != nil {
		return nil, nil, fmt.Errorf("stored signatures are unreadable: %w", err)
	}
	return doc, sigs, nil
}

// activeRelays reads every relay the registry should carry in one query, so a
// document is never built from a partial view.
func (p *Publisher) activeRelays(ctx context.Context) ([]RelayEntry, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT id, operator_id, host_id, role, host(ip), port, tls_name, static_pubkey
		   FROM relay_nodes
		  WHERE status = 'active'
		  ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]RelayEntry, 0)
	for rows.Next() {
		var e RelayEntry
		var pubkey []byte
		if err := rows.Scan(&e.ID, &e.OperatorID, &e.HostID, &e.Role,
			&e.IP, &e.Port, &e.TLSName, &pubkey); err != nil {
			return nil, err
		}
		e.StaticPubkey = hexOf(pubkey)
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (p *Publisher) remember(doc []byte, sigs []Signature, until time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lastDoc = doc
	p.lastSigs = sigs
	p.lastTil = until
}

// cached returns the last stored document while it is still within its own
// validity. It never extends valid_until.
func (p *Publisher) cached(now time.Time) ([]byte, []Signature, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.lastDoc == nil || !now.UTC().Before(p.lastTil) {
		return nil, nil, false
	}
	return p.lastDoc, p.lastSigs, true
}

const hexDigits = "0123456789abcdef"

func hexOf(b []byte) string {
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, hexDigits[c>>4], hexDigits[c&0x0f])
	}
	return string(out)
}
