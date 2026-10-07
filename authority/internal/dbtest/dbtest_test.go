package dbtest

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// unreachable names a socket directory with no server in it. Every case below passes
// it as the template url, so if the guard ever stopped running first the error would
// be a connection failure instead of ErrUnsafeName. That is what proves no statement
// is sent for a refused name.
const unreachable = "postgres:///quiethop_test?host=/var/empty&sslmode=disable"

func TestDropRefusesNamesOutsideTheTestNamespace(t *testing.T) {
	for _, name := range []string{
		"quiethop_test", // the template itself
		"postgres",      // the maintenance database
		"template1",
		"",
		"quiethop_testx",      // close, but not the prefix
		"QUIETHOP_TEST_upper", // wrong case, so outside [a-z0-9_]
		`quiethop_test_"; DROP DATABASE postgres; --`,
	} {
		err := Drop(context.Background(), unreachable, name)
		if err == nil {
			t.Errorf("Drop(%q) returned nil, expected a refusal", name)
			continue
		}
		if !errors.Is(err, ErrUnsafeName) {
			t.Errorf("Drop(%q) failed with %v, which is not the guard refusing it. "+
				"A connection error here would mean a statement was attempted.", name, err)
		}
	}
}

func TestCreateRefusesNamesOutsideTheTestNamespace(t *testing.T) {
	for _, name := range []string{"quiethop_test", "postgres", "", "other_db"} {
		_, err := Create(context.Background(), unreachable, name)
		if !errors.Is(err, ErrUnsafeName) {
			t.Errorf("Create(%q) failed with %v, expected the guard to refuse it", name, err)
		}
	}
}

func TestNameStaysWithinTheIdentifierLimit(t *testing.T) {
	for _, pkg := range []string{"handlers", "relay", "auth", strings.Repeat("verylongpackage", 8)} {
		name, err := Name(pkg)
		if err != nil {
			t.Fatalf("Name(%q): %v", pkg, err)
		}
		if len(name) > MaxNameLen {
			t.Errorf("Name(%q) = %q, %d bytes, over the %d byte limit", pkg, name, len(name), MaxNameLen)
		}
		if !strings.HasPrefix(name, Prefix) {
			t.Errorf("Name(%q) = %q, missing the %q prefix", pkg, name, Prefix)
		}
		if err := guard("quiethop_test", name); err != nil {
			t.Errorf("Name(%q) = %q, which its own guard rejects: %v", pkg, name, err)
		}
	}
}

func TestNameIsDistinctAcrossCalls(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		n, err := Name("handlers")
		if err != nil {
			t.Fatal(err)
		}
		if seen[n] {
			t.Fatalf("Name produced %q twice", n)
		}
		seen[n] = true
	}
}

// The socket form carries its host in the query string and has an empty authority, so
// a naive rebuild turns postgres:///db into postgres:/db, which is a different url.
func TestWithDatabaseKeepsEveryOtherParameter(t *testing.T) {
	got, err := WithDatabase(DefaultTemplateURL, "quiethop_test_handlers_1_abcd")
	if err != nil {
		t.Fatal(err)
	}
	want := "postgres:///quiethop_test_handlers_1_abcd?host=/var/run/postgresql&sslmode=disable"
	if got != want {
		t.Errorf("WithDatabase gave\n  %s\nwant\n  %s", got, want)
	}
}
