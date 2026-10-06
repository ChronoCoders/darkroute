// Command testdb applies the embedded migrations to the database named by
// TEST_DATABASE_URL.
//
// It exists because the database backed tests connect and assume the schema is
// already there; none of them migrate. Routing the test schema through
// db.RunMigrations, the same function cmd/authority calls at startup, keeps it
// from drifting away from the production schema, which a hand written copy of
// the DDL would eventually do.
package main

import (
	"log/slog"
	"os"

	"github.com/ChronoCoders/darkrouter/authority/internal/db"
)

func main() {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		slog.Error("TEST_DATABASE_URL is not set, so there is no database to migrate")
		os.Exit(1)
	}
	if err := db.RunMigrations(url); err != nil {
		slog.Error("applying the embedded migrations to the test database failed", "err", err)
		os.Exit(1)
	}
	slog.Info("test database schema is up to date")
}
