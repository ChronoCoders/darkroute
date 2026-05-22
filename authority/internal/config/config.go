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
		Port:            port,
		Environment:     os.Getenv("ENVIRONMENT"),
	}
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
	if c.Environment == "production" {
		if strings.Contains(c.DatabaseURL, "localhost") || strings.Contains(c.DatabaseURL, "127.0.0.1") {
			return errors.New("DATABASE_URL must not point to localhost or 127.0.0.1 in production")
		}
		for _, f := range forbiddenJWTSecrets() {
			if c.JWTSecret == f {
				return fmt.Errorf("JWT_SECRET matches a forbidden default value")
			}
		}
	}
	return nil
}
