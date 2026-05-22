package auth

import (
	"strings"
	"testing"
)

func TestJWTGenerateValidateRoundTrip(t *testing.T) {
	jm := NewJWTManager("this-is-a-test-secret-of-sufficient-length-32+")
	tok, err := jm.GenerateToken("sub-123", "operator", "free")
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	claims, err := jm.ValidateToken(tok)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if claims.Sub != "sub-123" {
		t.Errorf("sub: got %q", claims.Sub)
	}
	if claims.Role != "operator" {
		t.Errorf("role: got %q", claims.Role)
	}
	if claims.Tier != "free" {
		t.Errorf("tier: got %q", claims.Tier)
	}
}

func TestJWTRejectsWrongSecret(t *testing.T) {
	a := NewJWTManager("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	b := NewJWTManager("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	tok, err := a.GenerateToken("s", "r", "t")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.ValidateToken(tok); err == nil {
		t.Fatal("expected validation to fail with different secret")
	}
}

func TestJWTRejectsTamperedToken(t *testing.T) {
	jm := NewJWTManager("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	tok, err := jm.GenerateToken("s", "r", "t")
	if err != nil {
		t.Fatal(err)
	}
	tampered := tok + "x"
	if _, err := jm.ValidateToken(tampered); err == nil {
		t.Fatal("expected validation to fail for tampered token")
	}
	if strings.Count(tok, ".") != 2 {
		t.Errorf("expected JWT to have 3 segments")
	}
}
