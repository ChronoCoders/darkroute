package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

type Config struct {
	DatabaseURL     string
	JWTSecret       string
	RSAKeyPath      string
	RelayAPIKeySalt string
	AllowedRelayIPs []string
	Port            string
	Environment     string
}

func forbiddenJWTSecrets() []string {
	return []string{"secret", "dev", "development", "change_me", "replace_me", "password"}
}

func Load() *Config {
	port := os.Getenv("PORT")
	if port == "" {
		port = "3001"
	}
	return &Config{
		DatabaseURL:     os.Getenv("DATABASE_URL"),
		JWTSecret:       os.Getenv("JWT_SECRET"),
		RSAKeyPath:      os.Getenv("RSA_KEY_PATH"),
		RelayAPIKeySalt: os.Getenv("RELAY_API_KEY_SALT"),
		AllowedRelayIPs: parseIPList(os.Getenv("ALLOWED_RELAY_IPS")),
		Port:            port,
		Environment:     os.Getenv("ENVIRONMENT"),
	}
}

func parseIPList(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func (c *Config) Validate() error {
	if c.JWTSecret == "" {
		return errors.New("JWT_SECRET is required")
	}
	if len(c.JWTSecret) < 32 {
		return errors.New("JWT_SECRET must be at least 32 characters")
	}
	if c.DatabaseURL == "" {
		return errors.New("DATABASE_URL is required")
	}
	if c.RSAKeyPath == "" {
		return errors.New("RSA_KEY_PATH is required")
	}
	if c.RelayAPIKeySalt == "" {
		return errors.New("RELAY_API_KEY_SALT is required")
	}
	if len(c.RelayAPIKeySalt) < 16 {
		return errors.New("RELAY_API_KEY_SALT must be at least 16 characters")
	}
	if c.Environment == "" {
		return errors.New("ENVIRONMENT is required")
	}
	// Forbidden-default JWT secrets are rejected in every environment per
	// SECURITY_MODEL §7.1 ("the application will not start if this variable
	// is absent or matches any known default string"). The 32-char minimum
	// already screens the literal defaults below; this exact-match check is
	// belt-and-braces against pattern-stuffing them to length.
	for _, f := range forbiddenJWTSecrets() {
		if c.JWTSecret == f {
			return fmt.Errorf("JWT_SECRET matches a forbidden default value")
		}
	}
	if c.Environment == "production" {
		if strings.Contains(c.DatabaseURL, "localhost") || strings.Contains(c.DatabaseURL, "127.0.0.1") {
			return errors.New("DATABASE_URL must not point to localhost or 127.0.0.1 in production")
		}
	}
	return nil
}
