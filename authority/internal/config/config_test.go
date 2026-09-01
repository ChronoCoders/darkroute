package config

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func validBase() *Config {
	return &Config{
		DatabaseURL:     "postgres://u:p@db.example.com:5432/dr",
		JWTSecret:       strings.Repeat("a", 32),
		RSAKeyPath:      "./keys/authority.pem",
		RelayAPIKeySalt: "salt-of-sufficient-length-here",
		Port:            "3001",
		Environment:     "development",
	}
}

func TestValidateAcceptsValidConfig(t *testing.T) {
	if err := validBase().Validate(); err != nil {
		t.Fatalf("expected valid config to pass: %v", err)
	}
}

func TestValidateRejectsMissingJWTSecret(t *testing.T) {
	c := validBase()
	c.JWTSecret = ""
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for empty JWT_SECRET")
	}
}

func TestValidateRejectsShortJWTSecret(t *testing.T) {
	c := validBase()
	c.JWTSecret = strings.Repeat("a", 31)
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for short JWT_SECRET")
	}
}

func TestValidateRejectsMissingDatabaseURL(t *testing.T) {
	c := validBase()
	c.DatabaseURL = ""
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for missing DATABASE_URL")
	}
}

func TestValidateRejectsMissingRSAKeyPath(t *testing.T) {
	c := validBase()
	c.RSAKeyPath = ""
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for missing RSA_KEY_PATH")
	}
}

func TestValidateRejectsMissingRelayAPIKeySalt(t *testing.T) {
	c := validBase()
	c.RelayAPIKeySalt = ""
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for missing RELAY_API_KEY_SALT")
	}
}

func TestValidateRejectsShortRelayAPIKeySalt(t *testing.T) {
	c := validBase()
	c.RelayAPIKeySalt = "tooshort"
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for short RELAY_API_KEY_SALT")
	}
}

func TestValidateRejectsMissingEnvironment(t *testing.T) {
	c := validBase()
	c.Environment = ""
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for missing ENVIRONMENT")
	}
}

func TestValidateRejectsLocalhostInProduction(t *testing.T) {
	c := validBase()
	c.Environment = "production"
	c.DatabaseURL = "postgres://u:p@localhost:5432/dr"
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for localhost DATABASE_URL in production")
	}
	c.DatabaseURL = "postgres://u:p@127.0.0.1:5432/dr"
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for 127.0.0.1 DATABASE_URL in production")
	}
}

func TestValidateRejectsForbiddenJWTSecretsInEveryEnvironment(t *testing.T) {
	for _, env := range []string{"development", "production"} {
		for _, bad := range forbiddenJWTSecrets() {
			c := validBase()
			c.Environment = env
			c.JWTSecret = bad
			// short secrets fail the length check first; that's acceptable — both reject.
			if err := c.Validate(); err == nil {
				t.Fatalf("expected error for forbidden JWT_SECRET %q in %s", bad, env)
			}
		}
	}
}

func TestValidateAllowsLocalhostInDevelopment(t *testing.T) {
	c := validBase()
	c.DatabaseURL = "postgres://u:p@localhost:5432/dr"
	if err := c.Validate(); err != nil {
		t.Fatalf("expected localhost OK in development: %v", err)
	}
}

func TestValidateRejectsAbsentRSAKeyFileInProduction(t *testing.T) {
	c := validBase()
	c.Environment = "production"
	c.RSAKeyPath = filepath.Join(t.TempDir(), "absent", "authority.pem")

	err := c.Validate()
	if err == nil {
		t.Fatal("expected error for absent RSA key file in production")
	}
	// Validate formats the path with %q, which is strconv.Quote, so on Windows
	// every separator in the message is backslash-escaped and a raw comparison
	// against c.RSAKeyPath cannot match. Quoting the expected path the same way
	// pins the exact rendered form on both platforms.
	if !strings.Contains(err.Error(), strconv.Quote(c.RSAKeyPath)) {
		t.Errorf("error must name the failing path %s; got %v", strconv.Quote(c.RSAKeyPath), err)
	}
	if !strings.Contains(err.Error(), "not found or unreadable") {
		t.Errorf("error must say the key was not found; got %v", err)
	}
}

func TestValidateAcceptsExistingRSAKeyFileInProduction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authority.pem")
	if err := os.WriteFile(path, []byte("placeholder"), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	c := validBase()
	c.Environment = "production"
	c.RSAKeyPath = path

	if err := c.Validate(); err != nil {
		t.Fatalf("expected production config with an existing key file to pass: %v", err)
	}
}

// The development branch must stay permissive so blind.LoadOrGenerate can mint
// the first key on a fresh machine; TestLoadOrGenerateCreatesFileOnFirstRun in
// the blind package covers the generation itself.
func TestValidateAllowsAbsentRSAKeyFileOutsideProduction(t *testing.T) {
	c := validBase()
	c.RSAKeyPath = filepath.Join(t.TempDir(), "absent", "authority.pem")

	if err := c.Validate(); err != nil {
		t.Fatalf("expected absent key file to be allowed outside production: %v", err)
	}
}
