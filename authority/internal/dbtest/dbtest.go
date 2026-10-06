// Package dbtest gives each test package binary its own database, created from a
// migrated template.
//
// It exists because two packages writing one database race in a way no test can own.
// PickRandomActiveByRole selects from every active relay of a role by design, so the
// handlers tests can pick a guard row seeded by the relay package; when that package's
// cleanup deletes the row, the circuit_assignments insert fails
// circuit_assignments_guard_id_fkey. Measured at two failures in twenty full runs
// before this helper existed. Scoping assertions to rows a test created cannot fix it,
// because the production code under test chooses rows the test does not own.
//
// One database per package binary, not per test. Tests inside a package still share
// that database and still run sequentially, so their own checked cleanups stay
// meaningful.
//
// Imported only from _test files.
package dbtest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Prefix every database this helper may create or drop must carry. The template is
// darkrouter_test with no trailing underscore, so it can never match.
const Prefix = "darkrouter_test_"

// MaxNameLen is PostgreSQL's identifier limit. A longer name would be silently
// truncated, and two truncated names could collide.
const MaxNameLen = 63

const DefaultTemplateURL = "postgres:///darkrouter_test?host=/var/run/postgresql&sslmode=disable"

// forceDropMinVersion is the server_version_num from which DROP DATABASE accepts
// WITH (FORCE), which terminates other sessions rather than failing.
const forceDropMinVersion = 130000

var safeName = regexp.MustCompile(`^[a-z0-9_]+$`)

// ErrUnsafeName is returned before any statement is sent.
var ErrUnsafeName = errors.New("refusing to touch a database outside the test namespace")

// TemplateURL is the migrated template, from the environment or the built in default.
// Nothing connects to the template during a test run.
func TemplateURL() string {
	if v := os.Getenv("TEST_DATABASE_URL"); v != "" {
		return v
	}
	return DefaultTemplateURL
}

func databaseOf(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parse database url: %w", err)
	}
	name := strings.TrimPrefix(u.Path, "/")
	if name == "" {
		return "", errors.New("the database url names no database")
	}
	return name, nil
}

// WithDatabase returns raw pointed at a different database, keeping every other
// connection parameter. The socket form carries its host in the query string, so only
// the path changes.
func WithDatabase(raw, name string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parse database url: %w", err)
	}
	u.Path = "/" + name
	return u.String(), nil
}

// guard is the whole safety story, and it runs before any connection is opened.
func guard(template, name string) error {
	if !strings.HasPrefix(name, Prefix) {
		return fmt.Errorf("%w: %q does not start with %q", ErrUnsafeName, name, Prefix)
	}
	if name == template {
		return fmt.Errorf("%w: %q is the template", ErrUnsafeName, name)
	}
	if len(name) > MaxNameLen {
		return fmt.Errorf("%w: %q is %d bytes, over the %d byte limit",
			ErrUnsafeName, name, len(name), MaxNameLen)
	}
	if !safeName.MatchString(name) {
		return fmt.Errorf("%w: %q holds characters outside [a-z0-9_]", ErrUnsafeName, name)
	}
	return nil
}

// Name builds the per package database name, trimming the package label if the total
// would exceed the identifier limit rather than letting the server truncate it.
func Name(pkg string) (string, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("random suffix: %w", err)
	}
	suffix := fmt.Sprintf("_%d_%s", os.Getpid(), hex.EncodeToString(b))
	label := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return '_'
	}, strings.ToLower(pkg))
	room := MaxNameLen - len(Prefix) - len(suffix)
	if room < 1 {
		return "", errors.New("no room left for a package label in the name")
	}
	if len(label) > room {
		label = label[:room]
	}
	return Prefix + label + suffix, nil
}

func connect(ctx context.Context, dsn string) (*pgx.Conn, error) {
	c, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	return c, nil
}

// Create makes a database from the template and returns a url pointing at it.
func Create(ctx context.Context, templateURL, name string) (string, error) {
	template, err := databaseOf(templateURL)
	if err != nil {
		return "", err
	}
	if err := guard(template, name); err != nil {
		return "", err
	}
	adminURL, err := WithDatabase(templateURL, "postgres")
	if err != nil {
		return "", err
	}
	conn, err := connect(ctx, adminURL)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close(ctx) }()
	// Identifiers cannot be bound as parameters. Both names are quoted, and the new
	// one has already passed guard, so only [a-z0-9_] reaches the statement.
	stmt := fmt.Sprintf("CREATE DATABASE %q TEMPLATE %q", name, template)
	if _, err := conn.Exec(ctx, stmt); err != nil {
		return "", fmt.Errorf("create database %s from template %s: %w", name, template, err)
	}
	return WithDatabase(templateURL, name)
}

// Drop removes a database this helper created. The guard runs before any connection,
// so a refused name sends no statement at all.
func Drop(ctx context.Context, templateURL, name string) error {
	template, err := databaseOf(templateURL)
	if err != nil {
		return err
	}
	if err := guard(template, name); err != nil {
		return err
	}
	adminURL, err := WithDatabase(templateURL, "postgres")
	if err != nil {
		return err
	}
	conn, err := connect(ctx, adminURL)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close(ctx) }()

	stmt := fmt.Sprintf("DROP DATABASE IF EXISTS %q", name)
	if force, err := supportsForceDrop(ctx, conn); err == nil && force {
		stmt += " WITH (FORCE)"
	}
	if _, err := conn.Exec(ctx, stmt); err != nil {
		return fmt.Errorf("drop database %s: %w", name, err)
	}
	return nil
}

func supportsForceDrop(ctx context.Context, conn *pgx.Conn) (bool, error) {
	var raw string
	if err := conn.QueryRow(ctx, "SHOW server_version_num").Scan(&raw); err != nil {
		return false, err
	}
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return false, err
	}
	return n >= forceDropMinVersion, nil
}

// Run wraps TestMain. It creates this package's database, points TEST_DATABASE_URL at
// it so the existing pool helpers pick it up, runs the tests, and drops it.
//
// When the template is unreachable the tests are left to skip or fail on their own
// terms rather than being masked here, so a missing database still surfaces.
func Run(pkg string, run func() int) int {
	templateURL := TemplateURL()
	name, err := Name(pkg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dbtest: %v\n", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	dbURL, err := Create(ctx, templateURL, name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dbtest: %v\n", err)
		return 1
	}
	if err := os.Setenv("TEST_DATABASE_URL", dbURL); err != nil {
		fmt.Fprintf(os.Stderr, "dbtest: set TEST_DATABASE_URL: %v\n", err)
		return 1
	}

	code := run()

	dropCtx, dropCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer dropCancel()
	if err := Drop(dropCtx, templateURL, name); err != nil {
		fmt.Fprintf(os.Stderr, "dbtest: %v\n", err)
		if code == 0 {
			code = 1
		}
	}
	return code
}
