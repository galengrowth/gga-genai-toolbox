package util

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
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

func LogAndPostBilling(ctx context.Context, tool string, rowCount int, query string) {
	billingURL := BillingEndpointFromContext(ctx)
	if billingURL == "" {
		return
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
	go func() {
		data, err := json.Marshal(bi)
		if err != nil {
			return
		}
		req, err := http.NewRequestWithContext(ctx, "POST", billingURL, bytes.NewReader(data))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		http.DefaultClient.Do(req)
	}()
}

func BillingEndpointFromContext(ctx context.Context) string {
	if v, ok := ctx.Value("billingEndpoint").(string); ok {
		return v
	}
	return ""
}

func UserInfoFromContext(ctx context.Context) (sub, email string) {
	claims := JWTClaimsFromContext(ctx)
	if claims == nil {
		return
	}
	if s, ok := claims["sub"].(string); ok {
		sub = s
	}
	if e, ok := claims["email"].(string); ok {
		email = e
	}
	return
}

func RequestIDFromContext(ctx context.Context) string {
	if id, ok := ctx.Value("requestID").(string); ok {
		return id
	}
	return ""
}

func JWTClaimsFromContext(ctx context.Context) map[string]any {
	if claims, ok := ctx.Value("jwtClaims").(map[string]any); ok {
		return claims
	}
	return nil
}
