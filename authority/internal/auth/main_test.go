package auth

import (
	"os"
	"testing"

	"github.com/ChronoCoders/darkrouter/authority/internal/dbtest"
)

// This package's tests get a database of their own, created from the migrated
// template and dropped afterwards. Two packages writing one database race in a way no
// test can own: see internal/dbtest for the measurement that forced it.
func TestMain(m *testing.M) {
	os.Exit(dbtest.Run("auth", m.Run))
}
