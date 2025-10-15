package util

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type BillingInfo struct {
	UserSub   string `json:"user_sub,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
	Tool      string `json:"tool"`
	RowCount  int    `json:"row_count"`
	Query     string `json:"query,omitempty"`
	RequestID string `json:"request_id,omitempty"`
	Timestamp string `json:"timestamp"`
}

// Context keys (typed) used for billing helpers. Keep fallbacks for legacy string keys.
const (
	billingEndpointKey contextKey = "billingEndpoint"
	requestIDKey       contextKey = "requestID"
	jwtClaimsKey       contextKey = "jwtClaims"
	authHeaderKey      contextKey = "authorizationHeader"
	billingEnforceKey  contextKey = "billingEnforce"
)

// WithBillingEndpoint stores the billing endpoint URL in context.
func WithBillingEndpoint(ctx context.Context, url string) context.Context {
	return context.WithValue(ctx, billingEndpointKey, url)
}

// WithRequestID stores a request ID in context.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

// WithJWTClaims stores JWT claims in context.
func WithJWTClaims(ctx context.Context, claims map[string]any) context.Context {
	return context.WithValue(ctx, jwtClaimsKey, claims)
}

// WithAuthorizationHeader stores the raw Authorization header for downstream use (e.g., billing).
func WithAuthorizationHeader(ctx context.Context, authorization string) context.Context {
	return context.WithValue(ctx, authHeaderKey, authorization)
}

// WithBillingEnforcement sets whether billing POST must succeed to consider the operation successful.
// Presence implies explicit setting.
func WithBillingEnforcement(ctx context.Context, enforce bool) context.Context {
	return context.WithValue(ctx, billingEnforceKey, enforce)
}

// package-scoped HTTP client with a sane timeout to avoid hangs.
var billingHTTPClient = &http.Client{Timeout: 5 * time.Second}

func LogAndPostBilling(ctx context.Context, tool string, rowCount int, query string) {
	// Only perform billing when explicitly enabled via requireBillingPost=true
	if enforce, ok := BillingEnforcementFromContext(ctx); !ok || !enforce {
		return
	}
	billingURL := BillingEndpointFromContext(ctx)
	if billingURL == "" {
		return
	}
	// Determine if billing must succeed (default false)
	enforceBilling := false
	if v, ok := ctx.Value(billingEnforceKey).(bool); ok {
		enforceBilling = v
	}
	sub, email := UserInfoFromContext(ctx)
	reqID := RequestIDFromContext(ctx)
	bi := BillingInfo{
		UserSub:   sub,
		UserEmail: email,
		Tool:      tool,
		RowCount:  rowCount,
		Query:     query,
		RequestID: reqID,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
	// Best-effort async send, with proper timeout and error logging.
	// Avoid tying this to the parent request context (which may be canceled immediately).
	logger, _ := LoggerFromContext(ctx)
	userAgent, _ := UserAgentFromContext(ctx)

	go func(bURL, reqID string, payload BillingInfo) {
		// Marshal outside of request creation and log failures.
		data, err := json.Marshal(payload)
		if err != nil {
			if logger != nil {
				logger.ErrorContext(context.Background(), "billing: failed to marshal payload", "error", err)
			}
			return
		}

		// Use an isolated context with timeout to prevent leaks/hangs.
		reqCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, bURL, bytes.NewReader(data))
		if err != nil {
			if logger != nil {
				logger.ErrorContext(context.Background(), "billing: failed to create request", "error", err)
			}
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		if reqID != "" {
			req.Header.Set("X-Request-ID", reqID)
		}
		if userAgent != "" {
			req.Header.Set("User-Agent", userAgent)
		}
		if auth := AuthorizationHeaderFromContext(ctx); auth != "" {
			req.Header.Set("Authorization", auth)
		}

		// Optional debug: log a curl-equivalent command to reproduce the request
		if logger != nil {
			// Truncate payload for safety
			payloadStr := string(data)
			if len(payloadStr) > 4096 {
				payloadStr = payloadStr[:4096] + "...<truncated>"
			}
			// Build a simple, safe curl (single line)
			// Minimal quoting: wrap values in single quotes and escape any single quotes.
			esc := func(s string) string { return strings.ReplaceAll(s, "'", "'\\''") }
			parts := []string{"curl", "-X", "POST", "'" + esc(bURL) + "'", "-H", "'Content-Type: application/json'", "-H", "'Accept: application/json'"}
			if reqID != "" {
				parts = append(parts, "-H", "'X-Request-ID: "+esc(reqID)+"'")
			}
			if userAgent != "" {
				parts = append(parts, "-H", "'User-Agent: "+esc(userAgent)+"'")
			}
			if auth := AuthorizationHeaderFromContext(ctx); auth != "" {
				// Redact token for logs while preserving scheme (e.g., Bearer)
				redacted := auth
				if sp := strings.SplitN(auth, " ", 2); len(sp) == 2 {
					scheme := sp[0]
					tok := sp[1]
					if len(tok) > 16 {
						tok = tok[:8] + "..." + tok[len(tok)-4:]
					} else if len(tok) > 0 {
						tok = "<redacted>"
					}
					redacted = scheme + " " + tok
				} else {
					redacted = "<redacted>"
				}
				parts = append(parts, "-H", "'Authorization: "+esc(redacted)+"'")
			}
			parts = append(parts, "--data-raw", "'"+esc(payloadStr)+"'")
			curl := strings.Join(parts, " ")
			logger.DebugContext(context.Background(), "billing: POST", "curl", curl)
		}

		resp, err := billingHTTPClient.Do(req)
		if err != nil {
			if logger != nil {
				if enforceBilling {
					logger.ErrorContext(context.Background(), "billing: request failed", "error", err)
					// When enforcement is on, log a strong error to surface in ops; still async, so caller should perform sync check if needed.
					logger.ErrorContext(context.Background(), "billing: enforced failure")
				} else {
					logger.WarnContext(context.Background(), "billing: request failed", "error", err)
				}
			}
			return
		}
		defer resp.Body.Close()
		var snippet string
		if resp.ContentLength != 0 {
			if b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096)); len(b) > 0 {
				snippet = string(b)
			}
			// drain remaining, if any
			io.Copy(io.Discard, resp.Body)
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			if logger != nil {
				if snippet != "" {
					logger.WarnContext(context.Background(), "billing: non-success status", "status", resp.Status, "body", snippet)
				} else {
					logger.WarnContext(context.Background(), "billing: non-success status", "status", resp.Status)
				}
			}
			if enforceBilling {
				logger.ErrorContext(context.Background(), "billing: enforced failure due to non-2xx status", "status", resp.Status)
			}
		}
	}(billingURL, reqID, bi)
}

// PostBillingSync performs a synchronous billing POST and returns error on failure.
// Intended for optional enforcement paths. Uses a short timeout and propagates transport/status errors.
func PostBillingSync(ctx context.Context, billingURL, tool string, rowCount int, query string) error {
	if billingURL == "" {
		return nil
	}
	sub, email := UserInfoFromContext(ctx)
	reqID := RequestIDFromContext(ctx)
	payload := BillingInfo{
		UserSub:   sub,
		UserEmail: email,
		Tool:      tool,
		RowCount:  rowCount,
		Query:     query,
		RequestID: reqID,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	userAgent, _ := UserAgentFromContext(ctx)

	reqCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, billingURL, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if reqID != "" {
		req.Header.Set("X-Request-ID", reqID)
	}
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}
	if auth := AuthorizationHeaderFromContext(ctx); auth != "" {
		req.Header.Set("Authorization", auth)
	}

	resp, err := billingHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// Read snippet for diagnostics
	var snippet []byte
	if resp.ContentLength != 0 {
		snippet, _ = io.ReadAll(io.LimitReader(resp.Body, 2048))
		io.Copy(io.Discard, resp.Body)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if len(snippet) > 0 {
			return fmt.Errorf("billing non-success: %s, body: %s", resp.Status, string(snippet))
		}
		return fmt.Errorf("billing non-success: %s", resp.Status)
	}
	return nil
}

func BillingEndpointFromContext(ctx context.Context) string {
	// Prefer typed key, but support legacy string key for backward compatibility.
	if v, ok := ctx.Value(billingEndpointKey).(string); ok {
		return v
	}
	if v, ok := ctx.Value("billingEndpoint").(string); ok { // legacy
		return v
	}
	return ""
}

// BillingEnforcementFromContext returns (value, isSet). If not set, callers should preserve default behavior.
func BillingEnforcementFromContext(ctx context.Context) (bool, bool) {
	if v, ok := ctx.Value(billingEnforceKey).(bool); ok {
		return v, true
	}
	if v, ok := ctx.Value("requireBillingPost").(bool); ok {
		return v, true
	}
	return false, false
}

func UserInfoFromContext(ctx context.Context) (sub, email string) {
	claims := JWTClaimsFromContext(ctx)
	if claims == nil {
		return
	}
	if s, ok := claims["sub"].(string); ok {
		sub = s
	}
	// Try standard claim first
	if e, ok := claims["email"].(string); ok {
		email = e
	}
	// Try common alternates if standard email not present
	if email == "" {
		for _, k := range []string{"upn", "preferred_username"} {
			if v, ok := claims[k].(string); ok && isLikelyEmail(v) {
				email = v
				break
			}
		}
	}
	// Try namespaced/custom claims that include "email" in the key
	if email == "" {
		for k, v := range claims {
			if strings.Contains(strings.ToLower(k), "email") {
				if vs, ok := v.(string); ok && isLikelyEmail(vs) {
					email = vs
					break
				}
			}
		}
	}
	return
}

// isLikelyEmail does a light heuristic check for email-looking strings
func isLikelyEmail(s string) bool {
	if s == "" {
		return false
	}
	if !strings.Contains(s, "@") {
		return false
	}
	parts := strings.SplitN(s, "@", 2)
	return len(parts) == 2 && strings.Contains(parts[1], ".")
}

func RequestIDFromContext(ctx context.Context) string {
	if id, ok := ctx.Value(requestIDKey).(string); ok {
		return id
	}
	if id, ok := ctx.Value("requestID").(string); ok { // legacy
		return id
	}
	return ""
}

func JWTClaimsFromContext(ctx context.Context) map[string]any {
	if claims, ok := ctx.Value(jwtClaimsKey).(map[string]any); ok {
		return claims
	}
	if claims, ok := ctx.Value("jwtClaims").(map[string]any); ok { // legacy
		return claims
	}
	return nil
}

// AuthorizationHeaderFromContext retrieves the raw Authorization header if present.
func AuthorizationHeaderFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(authHeaderKey).(string); ok {
		return v
	}
	if v, ok := ctx.Value("authorizationHeader").(string); ok { // legacy
		return v
	}
	return ""
}
