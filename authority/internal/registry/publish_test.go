package registry

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ChronoCoders/quiethop/authority/internal/dbtest"
	"github.com/jackc/pgx/v5/pgxpool"
)

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	// Lazy, like the other database-backed packages: the package database is
	// created on the first test that asks. A failure is fatal rather than a
	// skip, because a skipped database test and a passing one read alike.
	url, err := dbtest.URL()
	if err != nil {
		t.Fatalf("test database: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func signerFor(t *testing.T) *Signer {
	t.Helper()
	path := filepath.Join(t.TempDir(), "registry.key")
	if _, err := GenerateKeyFile(path); err != nil {
		t.Fatalf("GenerateKeyFile: %v", err)
	}
	s, err := LoadSigner(path)
	if err != nil {
		t.Fatalf("LoadSigner: %v", err)
	}
	return s
}

// clearDocuments gives each test an empty table, because version is global and
// a leftover row from another test would change the expected serial.
func clearDocuments(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `DELETE FROM registry_documents`); err != nil {
		t.Fatalf("clear registry_documents: %v", err)
	}
}

// A second publisher instance against the same database in the same hour must
// return byte-identical output. This is the property an in-memory cache could
// not give, because a restart or a second instance would rebuild.
func TestSecondInstanceSameHourIsByteIdentical(t *testing.T) {
	pool := testPool(t)
	clearDocuments(t, pool)
	ctx := context.Background()
	now := time.Date(2026, 10, 7, 14, 30, 0, 0, time.UTC)

	a := NewPublisher(pool, signerFor(t))
	// A different signer, to prove the second instance serves the stored row
	// rather than signing again with its own key.
	b := NewPublisher(pool, signerFor(t))

	docA, sigsA, err := a.Current(ctx, now)
	if err != nil {
		t.Fatalf("first publisher: %v", err)
	}
	docB, sigsB, err := b.Current(ctx, now)
	if err != nil {
		t.Fatalf("second publisher: %v", err)
	}
	if !bytes.Equal(docA, docB) {
		t.Error("two instances in the same hour produced different document bytes")
	}
	if len(sigsA) != 1 || len(sigsB) != 1 {
		t.Fatalf("signature counts %d and %d, want 1 each", len(sigsA), len(sigsB))
	}
	if sigsA[0] != sigsB[0] {
		t.Errorf("signatures differ: %+v vs %+v", sigsA[0], sigsB[0])
	}

	var rows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM registry_documents`).Scan(&rows); err != nil {
		t.Fatalf("count: %v", err)
	}
	if rows != 1 {
		t.Errorf("stored %d rows for one hour, want 1", rows)
	}
}

// Concurrent first requests in a new hour must produce exactly one row and
// identical responses. The loser of the insert race serves the winner's bytes.
func TestConcurrentFirstRequestsProduceOneRow(t *testing.T) {
	pool := testPool(t)
	clearDocuments(t, pool)
	ctx := context.Background()
	now := time.Date(2026, 10, 7, 15, 5, 0, 0, time.UTC)

	const n = 8
	pubs := make([]*Publisher, n)
	for i := range pubs {
		pubs[i] = NewPublisher(pool, signerFor(t))
	}

	docs := make([][]byte, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			docs[i], _, errs[i] = pubs[i].Current(ctx, now)
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("publisher %d: %v", i, err)
		}
	}
	for i := 1; i < n; i++ {
		if !bytes.Equal(docs[0], docs[i]) {
			t.Fatalf("publisher %d served different bytes from publisher 0", i)
		}
	}
	var rows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM registry_documents`).Scan(&rows); err != nil {
		t.Fatalf("count: %v", err)
	}
	if rows != 1 {
		t.Errorf("stored %d rows after %d concurrent first requests, want 1", rows, n)
	}
}

// Two publishers whose clocks differ by an hour: the later hour always carries
// the higher version, whichever publishes first. A counted version could not
// give this, because the order of publication would decide the order of
// versions rather than the hour.
func TestLaterHourAlwaysHasTheHigherVersionWhicheverPublishesFirst(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	earlier := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	later := earlier.Add(time.Hour)

	// The slow instance publishes the earlier hour second, which is the order
	// that breaks a counter.
	for _, order := range []struct {
		name  string
		first time.Time
		then  time.Time
	}{
		{"later first", later, earlier},
		{"earlier first", earlier, later},
	} {
		clearDocuments(t, pool)
		fast := NewPublisher(pool, signerFor(t))
		slow := NewPublisher(pool, signerFor(t))

		if _, _, err := fast.Current(ctx, order.first); err != nil {
			t.Fatalf("%s: first publish: %v", order.name, err)
		}
		if _, _, err := slow.Current(ctx, order.then); err != nil {
			t.Fatalf("%s: second publish: %v", order.name, err)
		}

		verEarlier := storedVersion(t, pool, HourOf(earlier))
		verLater := storedVersion(t, pool, HourOf(later))
		if verLater <= verEarlier {
			t.Errorf("%s: later hour version %d is not above earlier hour version %d",
				order.name, verLater, verEarlier)
		}
		if want := VersionFor(HourOf(earlier)); verEarlier != want {
			t.Errorf("%s: earlier version %d, want %d", order.name, verEarlier, want)
		}
		if want := VersionFor(HourOf(later)); verLater != want {
			t.Errorf("%s: later version %d, want %d", order.name, verLater, want)
		}
	}
}

// The database holds the publisher to the derivation, so a row that disagrees
// cannot be stored even by a direct insert.
func TestCheckConstraintsRejectOffHourAndMismatchedVersion(t *testing.T) {
	pool := testPool(t)
	clearDocuments(t, pool)
	ctx := context.Background()
	hour := time.Date(2026, 10, 7, 11, 0, 0, 0, time.UTC)

	// Control: a correct row inserts.
	if _, err := pool.Exec(ctx,
		`INSERT INTO registry_documents (version, valid_after, document, signatures)
		 VALUES ($1, $2, $3, '[]'::jsonb)`,
		VersionFor(hour), hour, []byte("{}")); err != nil {
		t.Fatalf("control insert failed: %v", err)
	}

	// An off-hour valid_after.
	offHour := hour.Add(30 * time.Minute)
	if _, err := pool.Exec(ctx,
		`INSERT INTO registry_documents (version, valid_after, document, signatures)
		 VALUES ($1, $2, $3, '[]'::jsonb)`,
		VersionFor(offHour), offHour, []byte("{}")); err == nil {
		t.Error("an off-hour valid_after was stored")
	}

	// A version that does not match its hour.
	other := hour.Add(2 * time.Hour)
	if _, err := pool.Exec(ctx,
		`INSERT INTO registry_documents (version, valid_after, document, signatures)
		 VALUES ($1, $2, $3, '[]'::jsonb)`,
		VersionFor(hour)+1, other, []byte("{}")); err == nil {
		t.Error("a version that does not match its valid_after was stored")
	}
}

func storedVersion(t *testing.T, pool *pgxpool.Pool, hour time.Time) int64 {
	t.Helper()
	var v int64
	if err := pool.QueryRow(context.Background(),
		`SELECT version FROM registry_documents WHERE valid_after = $1`, hour).Scan(&v); err != nil {
		t.Fatalf("read version for %s: %v", hour, err)
	}
	return v
}

// version follows the hour and survives a publisher restart, which an
// in-memory counter would not.
func TestVersionIncreasesAcrossHoursAndSurvivesRestart(t *testing.T) {
	pool := testPool(t)
	clearDocuments(t, pool)
	ctx := context.Background()
	base := time.Date(2026, 10, 7, 16, 0, 0, 0, time.UTC)

	first := NewPublisher(pool, signerFor(t))
	docA, _, err := first.Current(ctx, base)
	if err != nil {
		t.Fatalf("hour one: %v", err)
	}
	verA := versionOf(t, docA)

	// A brand new Publisher stands in for a restarted process: no memory of
	// the previous hour, so the serial must come from the database.
	second := NewPublisher(pool, signerFor(t))
	docB, _, err := second.Current(ctx, base.Add(time.Hour))
	if err != nil {
		t.Fatalf("hour two after restart: %v", err)
	}
	verB := versionOf(t, docB)

	if verB <= verA {
		t.Errorf("version did not increase across hours: %d then %d", verA, verB)
	}
	// And it is the hour, not a count, so the gap is exactly one.
	if verB-verA != 1 {
		t.Errorf("consecutive hours differ by %d, want 1", verB-verA)
	}
	third := NewPublisher(pool, signerFor(t))
	docC, _, err := third.Current(ctx, base.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("hour three: %v", err)
	}
	if verC := versionOf(t, docC); verC <= verB {
		t.Errorf("version did not increase again: %d then %d", verB, verC)
	}
}

// The validity window in a published document must match the constants, since
// the client enforces them and a mismatch would reject every document.
func TestPublishedWindowsMatchTheConstants(t *testing.T) {
	pool := testPool(t)
	clearDocuments(t, pool)
	ctx := context.Background()
	now := time.Date(2026, 10, 7, 18, 42, 0, 0, time.UTC)

	doc, _, err := NewPublisher(pool, signerFor(t)).Current(ctx, now)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	var d Document
	if err := json.Unmarshal(doc, &d); err != nil {
		t.Fatalf("parse: %v", err)
	}
	hour := HourOf(now)
	if d.ValidAfter != stamp(hour) {
		t.Errorf("valid_after %q, want %q", d.ValidAfter, stamp(hour))
	}
	if d.FreshUntil != stamp(hour.Add(FreshWindow)) {
		t.Errorf("fresh_until %q, want %q", d.FreshUntil, stamp(hour.Add(FreshWindow)))
	}
	if d.ValidUntil != stamp(hour.Add(ValidWindow)) {
		t.Errorf("valid_until %q, want %q", d.ValidUntil, stamp(hour.Add(ValidWindow)))
	}
	// Z suffix, not a numeric offset: the client parses RFC 3339 UTC.
	for _, ts := range []string{d.ValidAfter, d.FreshUntil, d.ValidUntil} {
		if ts[len(ts)-1] != 'Z' {
			t.Errorf("timestamp %q does not end in Z", ts)
		}
	}
}

// A served document must carry a signature that verifies, which is the whole
// point of storing the signatures alongside the bytes.
func TestServedDocumentVerifiesUnderTheSigningKey(t *testing.T) {
	pool := testPool(t)
	clearDocuments(t, pool)
	ctx := context.Background()
	s := signerFor(t)
	doc, sigs, err := NewPublisher(pool, s).Current(ctx, time.Date(2026, 10, 7, 19, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if len(sigs) != 1 {
		t.Fatalf("signature count %d, want 1", len(sigs))
	}
	if sigs[0].KeyID != s.KeyID() {
		t.Errorf("key id %q, want %q", sigs[0].KeyID, s.KeyID())
	}
	raw := decodeB64(t, sigs[0].Sig)
	if !Verify(s.PublicKey(), doc, raw) {
		t.Error("the served document did not verify under its signing key")
	}
	// Control: the same signature must fail over altered bytes.
	altered := append([]byte{}, doc...)
	altered[0] ^= 0x01
	if Verify(s.PublicKey(), altered, raw) {
		t.Error("the signature verified over altered bytes")
	}
}

func versionOf(t *testing.T, doc []byte) int64 {
	t.Helper()
	var d Document
	if err := json.Unmarshal(doc, &d); err != nil {
		t.Fatalf("parse document: %v", err)
	}
	return d.Version
}

func decodeB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64: %v", err)
	}
	return b
}
