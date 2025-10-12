// Copyright 2024 Galen Growth
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hta

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc/v2" // Updated import for JWKS caching
	"github.com/golang-jwt/jwt/v5"     // New import for JWT handling
	"github.com/googleapis/genai-toolbox/internal/auth"
)

const AuthServiceKind string = "hta"

// validate interface
var _ auth.AuthServiceConfig = Config{}

// Auth service configuration for HTA (Auth0/JWT)
type Config struct {
	Name     string `yaml:"name" validate:"required"`
	Kind     string `yaml:"kind" validate:"required"`
	Domain   string `yaml:"domain" validate:"required,url"`
	Audience string `yaml:"audience" validate:"required,url"`
}

// Returns the auth service kind
func (cfg Config) AuthServiceConfigKind() string {
	return AuthServiceKind
}

// Initialize an HTA auth service (Auth0/JWT)
func (cfg Config) Initialize() (auth.AuthService, error) {
	jwksURL := fmt.Sprintf("https://%s/.well-known/jwks.json", strings.TrimPrefix(cfg.Domain, "https://"))

	// Configure JWKS caching
	options := keyfunc.Options{
		RefreshInterval:  time.Hour,       // Refresh JWKS every hour
		RefreshRateLimit: time.Minute * 5, // Limit failed lookup retries
	}

	jwks, err := keyfunc.Get(jwksURL, options)
	if err != nil {
		return nil, fmt.Errorf("failed to get JWKS from %s: %w", jwksURL, err)
	}

	a := &AuthService{
		Name:     cfg.Name,
		Kind:     AuthServiceKind,
		Domain:   cfg.Domain,
		Audience: cfg.Audience,
		JWKS:     jwks,
	}
	return a, nil
}

var _ auth.AuthService = AuthService{}

// AuthService stores Auth0/JWT validation info.
type AuthService struct {
	Name     string `yaml:"name"`
	Kind     string `yaml:"kind"`
	Domain   string `yaml:"domain"`
	Audience string `yaml:"audience"`
	JWKS     *keyfunc.JWKS
}

// Returns the auth service kind
func (a AuthService) AuthServiceKind() string {
	return AuthServiceKind
}

// Returns the name of the auth service
func (a AuthService) GetName() string {
	return a.Name
}

// Validates "Authorization: Bearer <token>" JWT, returning claims map if valid.
func (a AuthService) GetClaimsFromHeader(ctx context.Context, h http.Header) (map[string]any, error) {
	authHeader := h.Get("Authorization")
	if authHeader == "" {
		return nil, nil // No Authorization header, no token to validate
	}

	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		return nil, fmt.Errorf("authorization header must be in 'Bearer <token>' format")
	}
	token := strings.TrimSpace(authHeader[len(bearerPrefix):])
	if token == "" {
		return nil, fmt.Errorf("bearer token is empty")
	}

	parsedToken, err := jwt.Parse(token, a.JWKS.Keyfunc)
	if err != nil {
		return nil, fmt.Errorf("failed to parse or validate JWT: %w", err)
	}
	if !parsedToken.Valid {
		return nil, fmt.Errorf("invalid JWT token")
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid JWT claims format")
	}

	// Validate issuer (must be exactly "https://<domain>/")
	issuer, _ := claims["iss"].(string)
	expectedIssuer := "https://" + strings.TrimPrefix(a.Domain, "https://") + "/"
	if issuer != expectedIssuer {
		return nil, fmt.Errorf("invalid JWT issuer: expected %s, got %s", expectedIssuer, issuer)
	}

	// Validate audience (string or []interface{})
	audienceFound := false
	if audVal, ok := claims["aud"]; ok {
		switch aud := audVal.(type) {
		case string:
			if aud == a.Audience {
				audienceFound = true
			}
		case []interface{}:
			for _, v := range aud {
				if audStr, ok := v.(string); ok && audStr == a.Audience {
					audienceFound = true
					break
				}
			}
		}
	}
	if !audienceFound {
		return nil, fmt.Errorf("invalid JWT audience: expected %s", a.Audience)
	}

	return claims, nil
}
