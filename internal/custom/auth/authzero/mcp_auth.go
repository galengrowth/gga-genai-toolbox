// Copyright 2026 Galen Growth
//
// Licensed under the Apache License, Version 2.0 (the License);
// you may not use this file except in compliance with the License.

package authzero

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/googleapis/genai-toolbox/internal/auth/generic"
)

// ValidateMCPAuth enforces Bearer JWT validation for MCP HTTP requests (/mcp).
// It uses the same audience, issuer, and algorithm rules as GetClaimsFromHeader.
// GetClaimsFromHeader behavior is unchanged when mcpEnabled is true; tools/call still resolves claims from Authorization.
func (a *AuthService) ValidateMCPAuth(ctx context.Context, h http.Header) error {
	tokenString := h.Get("Authorization")
	if tokenString == "" {
		return &generic.MCPAuthError{Code: http.StatusUnauthorized, Message: "missing access token", ScopesRequired: a.ScopesRequired}
	}

	headerParts := strings.Split(tokenString, " ")
	if len(headerParts) != 2 || strings.ToLower(headerParts[0]) != "bearer" {
		return &generic.MCPAuthError{Code: http.StatusUnauthorized, Message: "authorization header must be in the format 'Bearer <token>'", ScopesRequired: a.ScopesRequired}
	}

	claims := jwt.MapClaims{}
	parsedToken, err := jwt.ParseWithClaims(headerParts[1], claims, a.kf.Keyfunc, jwt.WithLeeway(a.leeway))
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenNotValidYet) {
			return &generic.MCPAuthError{Code: http.StatusUnauthorized, Message: "invalid or expired token", ScopesRequired: a.ScopesRequired}
		}
		return &generic.MCPAuthError{Code: http.StatusUnauthorized, Message: "invalid or expired token", ScopesRequired: a.ScopesRequired}
	}
	if !parsedToken.Valid {
		return &generic.MCPAuthError{Code: http.StatusUnauthorized, Message: "invalid or expired token", ScopesRequired: a.ScopesRequired}
	}

	if m := parsedToken.Method; m != nil {
		alg := m.Alg()
		if !slices.Contains(a.allowedAlgs, alg) {
			return &generic.MCPAuthError{Code: http.StatusUnauthorized, Message: "invalid or expired token", ScopesRequired: a.ScopesRequired}
		}
	}

	issuer, _ := claims["iss"].(string)
	expectedIssuer := "https://" + a.Domain + "/"
	if issuer != expectedIssuer {
		return &generic.MCPAuthError{Code: http.StatusUnauthorized, Message: "invalid or expired token", ScopesRequired: a.ScopesRequired}
	}

	aud, err := claims.GetAudience()
	if err != nil {
		return &generic.MCPAuthError{Code: http.StatusUnauthorized, Message: "could not parse audience from token", ScopesRequired: a.ScopesRequired}
	}
	isAudValid := false
	for _, audItem := range aud {
		if audItem == a.Audience {
			isAudValid = true
			break
		}
	}
	if !isAudValid {
		return &generic.MCPAuthError{Code: http.StatusUnauthorized, Message: "audience validation failed", ScopesRequired: a.ScopesRequired}
	}

	if len(a.ScopesRequired) > 0 {
		scopeClaim, ok := claims["scope"].(string)
		if !ok {
			return &generic.MCPAuthError{Code: http.StatusForbidden, Message: "insufficient scopes", ScopesRequired: a.ScopesRequired}
		}
		tokenScopes := strings.Split(scopeClaim, " ")
		scopeMap := make(map[string]bool)
		for _, s := range tokenScopes {
			scopeMap[s] = true
		}
		for _, requiredScope := range a.ScopesRequired {
			if !scopeMap[requiredScope] {
				return &generic.MCPAuthError{Code: http.StatusForbidden, Message: "insufficient scopes", ScopesRequired: a.ScopesRequired}
			}
		}
	}

	return nil
}
