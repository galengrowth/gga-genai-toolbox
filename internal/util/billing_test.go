package util

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	ilog "github.com/googleapis/genai-toolbox/internal/log"
)

// noopLogger implements log.Logger for testing without output
type noopLogger struct{}

func (noopLogger) DebugContext(ctx context.Context, format string, args ...interface{}) {}
func (noopLogger) InfoContext(ctx context.Context, format string, args ...interface{})  {}
func (noopLogger) WarnContext(ctx context.Context, format string, args ...interface{})  {}
func (noopLogger) ErrorContext(ctx context.Context, format string, args ...interface{}) {}

var _ ilog.Logger = (*noopLogger)(nil)

func TestContextKeys_TypedAndLegacy(t *testing.T) {
	base := context.Background()

	// Typed setters
	claims := map[string]any{"sub": "abc", "email": "user@example.com"}
	ctx := WithBillingEndpoint(base, "http://example.com/bill")
	ctx = WithRequestID(ctx, "rid-123")
	ctx = WithJWTClaims(ctx, claims)

	if got := BillingEndpointFromContext(ctx); got != "http://example.com/bill" {
		t.Fatalf("typed key: billing endpoint mismatch: %q", got)
	}
	if got := RequestIDFromContext(ctx); got != "rid-123" {
		t.Fatalf("typed key: request id mismatch: %q", got)
	}
	s, e := UserInfoFromContext(ctx)
	if s != "abc" || e != "user@example.com" {
		t.Fatalf("typed key: user info mismatch: %q %q", s, e)
	}

	// Legacy string keys
	legacy := context.WithValue(base, "billingEndpoint", "http://legacy/bill")
	legacy = context.WithValue(legacy, "requestID", "legacy-req")
	legacy = context.WithValue(legacy, "jwtClaims", claims)

	if got := BillingEndpointFromContext(legacy); got != "http://legacy/bill" {
		t.Fatalf("legacy key: billing endpoint mismatch: %q", got)
	}
	if got := RequestIDFromContext(legacy); got != "legacy-req" {
		t.Fatalf("legacy key: request id mismatch: %q", got)
	}
	s, e = UserInfoFromContext(legacy)
	if s != "abc" || e != "user@example.com" {
		t.Fatalf("legacy key: user info mismatch: %q %q", s, e)
	}
}

func TestLogAndPostBilling_SendsRequest(t *testing.T) {
	var received int32
	var gotUA string
	var gotReqID string
	var gotPayload BillingInfo

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&received, 1)
		gotUA = r.Header.Get("User-Agent")
		gotReqID = r.Header.Get("X-Request-ID")
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(&gotPayload); err != nil {
			t.Logf("failed to decode payload: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer ts.Close()

	ctx := context.Background()
	ctx = WithBillingEndpoint(ctx, ts.URL)
	ctx = WithRequestID(ctx, "req-xyz")
	ctx = WithUserAgent(ctx, "test/1.0")
	ctx = WithLogger(ctx, noopLogger{})

	LogAndPostBilling(ctx, "testTool", 42, "select 1")

	// wait up to 2 seconds for async send
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&received) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if atomic.LoadInt32(&received) == 0 {
		t.Fatalf("billing request not received")
	}
	if gotUA != "genai-toolbox/test/1.0" && gotUA != "test/1.0" {
		// Depending on WithUserAgent format, accept either
		t.Fatalf("unexpected user agent: %q", gotUA)
	}
	if gotReqID != "req-xyz" {
		t.Fatalf("unexpected request id header: %q", gotReqID)
	}
	if gotPayload.Tool != "testTool" || gotPayload.RowCount != 42 {
		t.Fatalf("unexpected payload: %+v", gotPayload)
	}
}

func TestLogAndPostBilling_NoEndpoint_NoPanic(t *testing.T) {
	ctx := context.Background()
	// no endpoint set
	LogAndPostBilling(ctx, "tool", 1, "q")
	// If we reach here without panic or hang, it's fine
}

func TestLogAndPostBilling_ForwardsAuthorization(t *testing.T) {
	var gotAuth string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	ctx := context.Background()
	ctx = WithBillingEndpoint(ctx, ts.URL)
	ctx = WithAuthorizationHeader(ctx, "Bearer test-token-123")
	ctx = WithLogger(ctx, noopLogger{})

	LogAndPostBilling(ctx, "tool", 0, "")

	// wait briefly for async send
	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		if gotAuth != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if gotAuth != "Bearer test-token-123" {
		t.Fatalf("authorization header not forwarded, got: %q", gotAuth)
	}
}

func TestPostBillingSync_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	ctx := context.Background()
	if err := PostBillingSync(ctx, ts.URL, "tool", 1, ""); err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
}

func TestPostBillingSync_Non2xx(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "fail", http.StatusInternalServerError)
	}))
	defer ts.Close()

	ctx := context.Background()
	if err := PostBillingSync(ctx, ts.URL, "tool", 1, ""); err == nil {
		t.Fatalf("expected error on non-2xx status")
	}
}

func TestBillingEnforcementFromContext(t *testing.T) {
	ctx := context.Background()
	if v, ok := BillingEnforcementFromContext(ctx); ok {
		t.Fatalf("expected not set, got ok=%v v=%v", ok, v)
	}
	ctx = WithBillingEnforcement(ctx, true)
	if v, ok := BillingEnforcementFromContext(ctx); !ok || !v {
		t.Fatalf("expected set=true, got ok=%v v=%v", ok, v)
	}
}
