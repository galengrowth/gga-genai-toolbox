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

package authzero

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc/v2" // JWKS caching
	"github.com/golang-jwt/jwt/v5"     // JWT handling
	"github.com/googleapis/genai-toolbox/internal/auth"
)

// AuthServiceKind is the canonical kind string for this AuthZero auth service.
const AuthServiceKind string = "authzero"

// validate interface
var _ auth.AuthServiceConfig = Config{}

// Config is the AuthZero (OIDC/JWT) service configuration.
type Config struct {
	Name        string   `yaml:"name" validate:"required"`
	Kind        string   `yaml:"kind" validate:"required"`
	Domain      string   `yaml:"domain" validate:"required,url"`
	Audience    string   `yaml:"audience" validate:"required,url"`
	AllowedAlgs []string `yaml:"allowedAlgs" validate:"omitempty"` // default: ["RS256"]
	Leeway      string   `yaml:"leeway" validate:"omitempty"`      // Go duration; default 30s
}

// AuthServiceConfigKind returns the kind for config implementations.
func (cfg Config) AuthServiceConfigKind() string { return AuthServiceKind }

// Initialize builds the AuthZero auth service using JWKS for key discovery.
func (cfg Config) Initialize() (auth.AuthService, error) {
	// Normalize domain (remove scheme, trailing slash)
	host := strings.TrimSuffix(strings.TrimPrefix(cfg.Domain, "https://"), "/")
	if host == "" {
		return nil, fmt.Errorf("domain must not be empty after normalization")
	}
	jwksURL := fmt.Sprintf("https://%s/.well-known/jwks.json", host)

	// Defaults
	allowedAlgs := cfg.AllowedAlgs
	if len(allowedAlgs) == 0 {
		allowedAlgs = []string{"RS256"}
	}
	leeway := 30 * time.Second
	if cfg.Leeway != "" {
		d, err := time.ParseDuration(cfg.Leeway)
		if err != nil || d < 0 {
			return nil, fmt.Errorf("invalid leeway duration %q: %w", cfg.Leeway, err)
		}
		leeway = d
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	options := keyfunc.Options{
		RefreshInterval:  time.Hour,
		RefreshRateLimit: 5 * time.Minute,
		RefreshErrorHandler: func(err error) {
			logger.Warn("jwks_refresh_failed", "url", jwksURL, "error", err.Error())
		},
	}
	jwks, err := keyfunc.Get(jwksURL, options)
	if err != nil {
		return nil, fmt.Errorf("failed to get JWKS from %s: %w", jwksURL, err)
	}
	logger.Info("jwks_loaded", "url", jwksURL)
	return &AuthService{
		Config:      cfg,
		Domain:      host,
		Audience:    cfg.Audience,
		JWKS:        jwks,
		allowedAlgs: allowedAlgs,
		leeway:      leeway,
		logger:      logger,
	}, nil
}

var _ auth.AuthService = (*AuthService)(nil)

// AuthService validates AuthZero-issued JWT access tokens.
type AuthService struct {
	Config
	Domain      string
	Audience    string
	JWKS        *keyfunc.JWKS
	allowedAlgs []string
	leeway      time.Duration
	logger      *slog.Logger
}

// AuthServiceKind returns the canonical kind string.
func (a *AuthService) AuthServiceKind() string { return AuthServiceKind }

// GetName returns the configured name of this auth service.
func (a *AuthService) GetName() string { return a.Name }

// ToConfig returns the configuration for this auth service.
func (a *AuthService) ToConfig() auth.AuthServiceConfig {
	return a.Config
}

// GetClaimsFromHeader parses and validates a Bearer token from HTTP headers.
// Sentinel errors for programmatic handling/log categorization.
var (
	ErrMissingAuthHeader   = errors.New("missing authorization header")
	ErrMalformedAuthHeader = errors.New("malformed authorization header")
	ErrEmptyToken          = errors.New("empty bearer token")
	ErrParseToken          = errors.New("unable to parse token")
	ErrInvalidToken        = errors.New("invalid token")
	ErrIssuerMismatch      = errors.New("issuer mismatch")
	ErrAudienceMismatch    = errors.New("audience mismatch")
	ErrExpiredToken        = errors.New("token expired or not yet valid")
	ErrAlgorithmNotAllowed = errors.New("jwt signing algorithm not allowed")
)

func (a *AuthService) GetClaimsFromHeader(ctx context.Context, h http.Header) (map[string]any, error) {
	authHeader := h.Get("Authorization")
	if authHeader == "" {
		return nil, nil
	} // treat as anonymous (not an auth error)
	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		return nil, ErrMalformedAuthHeader
	}
	tokenStr := strings.TrimSpace(authHeader[len(bearerPrefix):])
	if tokenStr == "" {
		return nil, ErrEmptyToken
	}

	claims := jwt.MapClaims{}
	parsedToken, err := jwt.ParseWithClaims(tokenStr, claims, a.JWKS.Keyfunc, jwt.WithLeeway(a.leeway))
	if err != nil {
		a.logger.Debug("jwt_parse_error", "error", err.Error())
		// Distinguish expiration / nbf errors
		if errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenNotValidYet) {
			return nil, ErrExpiredToken
		}
		// Detect JWKS alg mismatch (keyfunc error before method check)
		if strings.Contains(err.Error(), "JWK \"alg\" parameter value") {
			return nil, ErrAlgorithmNotAllowed
		}
		return nil, fmt.Errorf("%w: %v", ErrParseToken, err)
	}
	if !parsedToken.Valid {
		return nil, ErrInvalidToken
	}
	// Enforce allowed algorithms
	if m := parsedToken.Method; m != nil {
		alg := m.Alg()
		if !slices.Contains(a.allowedAlgs, alg) {
			return nil, ErrAlgorithmNotAllowed
		}
	}
	// Issuer check (normalized)
	issuer, _ := claims["iss"].(string)
	expectedIssuer := "https://" + a.Domain + "/"
	if issuer != expectedIssuer {
		return nil, fmt.Errorf("%w: expected %s got %s", ErrIssuerMismatch, expectedIssuer, issuer)
	}
	// Manual audience validation (supports string or array) to allow sentinel error mapping
	audRaw, hasAud := claims["aud"]
	if !hasAud {
		return nil, ErrAudienceMismatch
	}
	audOK := false
	switch audVal := audRaw.(type) {
	case string:
		audOK = audVal == a.Audience
	case []interface{}:
		for _, v := range audVal {
			if s, ok := v.(string); ok && s == a.Audience {
				audOK = true
				break
			}
		}
	}
	if !audOK {
		return nil, ErrAudienceMismatch
	}

	return claims, nil
}
