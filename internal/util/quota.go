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

// Quota preflight contract
// Request: { user_sub, user_email, tool, requested_rows?, request_id, timestamp }
// Response on success (200/204): { remaining_rows: int, reason?: string }
//  - remaining_rows == -1 => unlimited; treat as allowed
//  - remaining_rows > 0    => allowed
//  - remaining_rows == 0   => denied
// Error statuses like 429/403 should include { remaining_rows, reason } when possible

type QuotaCheckRequest struct {
	UserSub       string `json:"user_sub,omitempty"`
	UserEmail     string `json:"user_email,omitempty"`
	Tool          string `json:"tool"`
	RequestedRows *int   `json:"requested_rows,omitempty"`
	RequestID     string `json:"request_id,omitempty"`
	Timestamp     string `json:"timestamp"`
}

type QuotaCheckResponse struct {
	RemainingRows int    `json:"remaining_rows"`
	Reason        string `json:"reason,omitempty"`
}

// Typed context key
const (
	quotaEndpointKey contextKey = "quotaEndpoint"
)

func WithQuotaEndpoint(ctx context.Context, url string) context.Context {
	return context.WithValue(ctx, quotaEndpointKey, url)
}

func QuotaEndpointFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(quotaEndpointKey).(string); ok {
		return v
	}
	if v, ok := ctx.Value("quotaEndpoint").(string); ok { // legacy
		return v
	}
	return ""
}

// No additional flags; presence of quotaEndpoint implies strict enforcement.

// Shared HTTP client for quota checks
var quotaHTTPClient = &http.Client{Timeout: 5 * time.Second}

// CheckQuotaAndAuthorize returns (allowed, remainingRows, reason, err).
// - err is for transport/parse issues; when err != nil, the caller can decide to allow based on AllowOnQuotaError.
// - when err == nil and allowed == false, the caller should deny with 429 and include reason if provided.
func CheckQuotaAndAuthorize(ctx context.Context, tool string, requestedRows *int) (bool, int, string, error) {
	endpoint := QuotaEndpointFromContext(ctx)
	if endpoint == "" {
		return false, 0, "quota endpoint not configured", fmt.Errorf("quota endpoint not configured")
	}

	sub, email := UserInfoFromContext(ctx)
	reqID := RequestIDFromContext(ctx)
	payload := QuotaCheckRequest{
		UserSub:       sub,
		UserEmail:     email,
		Tool:          tool,
		RequestedRows: requestedRows,
		RequestID:     reqID,
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return false, 0, "marshal error", err
	}

	logger, _ := LoggerFromContext(ctx)
	userAgent, _ := UserAgentFromContext(ctx)

	reqCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return false, 0, "request build error", err
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

	// Optional debug curl (token redacted)
	if logger != nil {
		esc := func(s string) string { return strings.ReplaceAll(s, "'", "'\\''") }
		payloadStr := string(data)
		if len(payloadStr) > 4096 {
			payloadStr = payloadStr[:4096] + "...<truncated>"
		}
		parts := []string{"curl", "-X", "POST", "'" + esc(endpoint) + "'", "-H", "'Content-Type: application/json'", "-H", "'Accept: application/json'"}
		if reqID != "" {
			parts = append(parts, "-H", "'X-Request-ID: "+esc(reqID)+"'")
		}
		if userAgent != "" {
			parts = append(parts, "-H", "'User-Agent: "+esc(userAgent)+"'")
		}
		if auth := AuthorizationHeaderFromContext(ctx); auth != "" {
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
		logger.DebugContext(context.Background(), "quota: POST", "curl", curl)
	}

	resp, err := quotaHTTPClient.Do(req)
	if err != nil {
		return false, 0, "quota request failed", err
	}
	defer resp.Body.Close()

	// Read small body for messages
	var bodySnippet []byte
	if resp.ContentLength != 0 {
		bodySnippet, _ = io.ReadAll(io.LimitReader(resp.Body, 4096))
		io.Copy(io.Discard, resp.Body)
	}

	// Parse response JSON if available
	parseRemaining := func(b []byte) (int, string) {
		var q QuotaCheckResponse
		if len(b) == 0 {
			return 0, ""
		}
		if err := json.Unmarshal(b, &q); err != nil {
			return 0, string(b)
		}
		return q.RemainingRows, q.Reason
	}

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		remaining, reason := parseRemaining(bodySnippet)
		if remaining == -1 || remaining > 0 {
			return true, remaining, reason, nil
		}
		// If API returns 200 with 0, treat as denied but not an error
		return false, remaining, reason, nil
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusForbidden:
		remaining, reason := parseRemaining(bodySnippet)
		return false, remaining, reason, nil
	default:
		// Other server/client errors → return transport error for caller policy
		msg := fmt.Sprintf("quota unexpected status: %s", resp.Status)
		if len(bodySnippet) > 0 {
			msg = fmt.Sprintf("%s, body: %s", msg, string(bodySnippet))
		}
		return false, 0, msg, fmt.Errorf("%s", msg)
	}
}
