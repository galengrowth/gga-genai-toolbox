// Copyright 2026 Galen Growth

package authzero

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/googleapis/genai-toolbox/internal/auth/generic"
)

func TestValidateMCPAuth_MissingToken(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	svc := newService(t, buildJWKS(&priv.PublicKey, "kid1"), []string{"RS256"})
	svc.ScopesRequired = []string{"read:tools"}

	err := svc.ValidateMCPAuth(context.Background(), http.Header{})
	var mcpErr *generic.MCPAuthError
	if !errors.As(err, &mcpErr) || mcpErr.Code != http.StatusUnauthorized {
		t.Fatalf("expected MCPAuthError 401, got %v", err)
	}
}

func TestValidateMCPAuth_ValidToken(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	svc := newService(t, buildJWKS(&priv.PublicKey, "kid1"), []string{"RS256"})
	svc.ScopesRequired = []string{"openid"}

	claims := jwt.MapClaims{
		"iss":   "https://tenant.example.com/",
		"aud":   []string{"https://api.example.com"},
		"sub":   "user-123",
		"scope": "openid profile",
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
		"iat":   time.Now().Unix(),
	}
	tok := signToken(t, priv, "kid1", "RS256", claims)
	hdr := http.Header{"Authorization": []string{"Bearer " + tok}}

	err := svc.ValidateMCPAuth(context.Background(), hdr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateMCPAuth_InsufficientScope(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	svc := newService(t, buildJWKS(&priv.PublicKey, "kid1"), []string{"RS256"})
	svc.ScopesRequired = []string{"required.scope"}

	claims := jwt.MapClaims{
		"iss":   "https://tenant.example.com/",
		"aud":   []string{"https://api.example.com"},
		"sub":   "user-123",
		"scope": "openid",
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
		"iat":   time.Now().Unix(),
	}
	tok := signToken(t, priv, "kid1", "RS256", claims)
	hdr := http.Header{"Authorization": []string{"Bearer " + tok}}

	err := svc.ValidateMCPAuth(context.Background(), hdr)
	var mcpErr *generic.MCPAuthError
	if !errors.As(err, &mcpErr) || mcpErr.Code != http.StatusForbidden {
		t.Fatalf("expected MCPAuthError 403, got %v", err)
	}
}

func TestConfig_Initialize_McpEnabledRequiresAuthorizationServer(t *testing.T) {
	cfg := Config{
		Name:        "a",
		Type:        AuthServiceType,
		Domain:      "https://tenant.example.com",
		Audience:    "https://api.example.com",
		McpEnabled:  true,
		// AuthorizationServer intentionally empty
	}
	_, err := cfg.Initialize()
	if err == nil {
		t.Fatal("expected error when mcpEnabled without authorizationServer")
	}
}
