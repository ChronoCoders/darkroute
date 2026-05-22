package config

import (
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

func TestValidateRejectsForbiddenJWTSecretsInProduction(t *testing.T) {
	for _, bad := range forbiddenJWTSecrets() {
		c := validBase()
		c.Environment = "production"
		c.JWTSecret = bad
		// short secrets fail the length check first; that's acceptable — both reject.
		if err := c.Validate(); err == nil {
			t.Fatalf("expected error for forbidden JWT_SECRET %q in production", bad)
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
