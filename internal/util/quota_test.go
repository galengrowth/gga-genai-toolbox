package util

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestQuotaEnforcementFromContext(t *testing.T) {
	ctx := context.Background()
	if v, ok := QuotaEnforcementFromContext(ctx); ok {
		t.Fatalf("expected not set, got ok=%v v=%v", ok, v)
	}
	ctx = WithQuotaEnforcement(ctx, true)
	if v, ok := QuotaEnforcementFromContext(ctx); !ok || !v {
		t.Fatalf("expected set=true, got ok=%v v=%v", ok, v)
	}
}

func TestCheckQuotaAndAuthorize_NoEndpoint(t *testing.T) {
	ctx := context.Background()
	allowed, _, _, err := CheckQuotaAndAuthorize(ctx, "tool", nil)
	if err == nil || allowed {
		t.Fatalf("expected error and not allowed when endpoint missing")
	}
}

func TestCheckQuotaAndAuthorize_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"allowed": true}`))
	}))
	defer ts.Close()
	ctx := WithQuotaEndpoint(context.Background(), ts.URL)
	allowed, rem, _, err := CheckQuotaAndAuthorize(ctx, "tool", nil)
	if err != nil || !allowed || rem != -1 {
		t.Fatalf("unexpected: allowed=%v rem=%d err=%v", allowed, rem, err)
	}
}
