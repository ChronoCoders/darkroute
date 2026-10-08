package registry

import (
	"os"
	"testing"

	"github.com/ChronoCoders/quiethop/authority/internal/dbtest"
)

// This package gets its own database from the migrated template, as every
// database-backed package does. version in registry_documents is global, so
// sharing a database with another package would make the serial unpredictable.
func TestMain(m *testing.M) {
	os.Exit(dbtest.Run("registry", m.Run))
}
