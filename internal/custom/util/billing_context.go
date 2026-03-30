// Copyright 2026 Galen Growth
//
// Licensed under the Apache License, Version 2.0 (the License);
// you may not use this file except in compliance with the License.

package util

import (
	"context"
	"net/http"

	baseutil "github.com/googleapis/genai-toolbox/internal/util"
)

// EnrichContextWithAuthForBillingQuota attaches Authorization and JWT claims to ctx so
// billing and quota outbound HTTP calls can forward the client token and resolve user_sub / email.
func EnrichContextWithAuthForBillingQuota(ctx context.Context, header http.Header, claimsFromAuth map[string]map[string]any) context.Context {
	if header != nil {
		if auth := header.Get("Authorization"); auth != "" {
			ctx = baseutil.WithAuthorizationHeader(ctx, auth)
		}
	}
	for _, claims := range claimsFromAuth {
		if len(claims) > 0 {
			ctx = baseutil.WithJWTClaims(ctx, claims)
			break
		}
	}
	return ctx
}

// QuotaPreflightBeforeInvoke runs quota preflight when quotaEndpoint is configured.
// Returns *baseutil.ClientServerError with 503 (transport/upstream) or 429 (denied), matching historical REST/MCP mapping.
func QuotaPreflightBeforeInvoke(ctx context.Context, toolName string) error {
	_, err := PerformPreflightCheck(ctx, toolName)
	return err
}
