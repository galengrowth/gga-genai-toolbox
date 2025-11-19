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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/googleapis/genai-toolbox/internal/auth"
)

// AuthServiceKind is the kind string for the custom HTA auth service.
// This service delegates token validation to an external HTTP endpoint that
// returns an allow/deny style response (plus optional claims) via POST.
const AuthServiceKind string = "hta"

// validate interface
var _ auth.AuthServiceConfig = Config{}

// Auth service configuration for AuthZero (JWT)
type Config struct {
	Name         string `yaml:"name" validate:"required"`
	Kind         string `yaml:"kind" validate:"required"`
	AuthEndpoint string `yaml:"authEndPoint" validate:"required,url"`
	// Optional timeout for outbound auth POST (default 5s)
	Timeout string `yaml:"timeout" validate:"omitempty"`
}

// Returns the auth service kind
func (cfg Config) AuthServiceConfigKind() string {
	return AuthServiceKind
}

// Initialize an AuthZero auth service (JWT over Auth0 domain style)
func (cfg Config) Initialize() (auth.AuthService, error) {
	to := 5 * time.Second
	if cfg.Timeout != "" {
		if d, err := time.ParseDuration(cfg.Timeout); err == nil && d > 0 {
			to = d
		} else if err != nil {
			return nil, fmt.Errorf("invalid timeout value %q: %w", cfg.Timeout, err)
		}
	}
	return &AuthService{
		Config:       cfg,
		authEndpoint: cfg.AuthEndpoint,
		timeout:      to,
		client:       &http.Client{Timeout: to},
	}, nil
}

var _ auth.AuthService = (*AuthService)(nil)

// AuthService stores AuthZero/JWT validation info.
type AuthService struct {
	Config
	authEndpoint string
	timeout      time.Duration
	client       *http.Client
}

// Returns the auth service kind
func (a *AuthService) AuthServiceKind() string { return AuthServiceKind }

// Returns the name of the auth service
func (a *AuthService) GetName() string { return a.Name }

// ToConfig returns the configuration for this auth service.
func (a *AuthService) ToConfig() auth.AuthServiceConfig {
	return a.Config
}

// Validates "Authorization: Bearer <token>" JWT, returning claims map if valid.
func (a *AuthService) GetClaimsFromHeader(ctx context.Context, h http.Header) (map[string]any, error) {
	authHeader := h.Get("Authorization")
	if authHeader == "" {
		return nil, nil
	}
	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		return nil, fmt.Errorf("authorization header must be in 'Bearer <token>' format")
	}
	token := strings.TrimSpace(authHeader[len(bearerPrefix):])
	if token == "" {
		return nil, fmt.Errorf("bearer token is empty")
	}

	// Build request payload with token in body
	reqBody := map[string]string{"token": token}
	b, _ := json.Marshal(reqBody)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, a.authEndpoint, bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("creating auth request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("auth endpoint request failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("auth endpoint rejected token: status=%d body=%s", resp.StatusCode, truncateForLog(string(body), 300))
	}

	// Decode the entire response as claims (matching the working old implementation)
	var claims map[string]any
	if len(body) == 0 {
		return nil, errors.New("empty response from auth endpoint")
	}
	if err := json.Unmarshal(body, &claims); err != nil {
		return nil, fmt.Errorf("failed to decode claims from auth endpoint response: %w", err)
	}
	return claims, nil
}

func truncateForLog(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
