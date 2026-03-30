package util

import (
	"context"
	"testing"
)

func TestBillingInsufficientTokensBlocked_roundTrip(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ctx = WithJWTClaims(ctx, map[string]any{"sub": "user-1"})
	if BillingInsufficientTokensBlocked(ctx) {
		t.Fatal("unexpected block")
	}
	SetBillingInsufficientTokensBlock(ctx)
	if !BillingInsufficientTokensBlocked(ctx) {
		t.Fatal("expected block after set")
	}
	ClearBillingInsufficientTokensBlock(ctx)
	if BillingInsufficientTokensBlocked(ctx) {
		t.Fatal("unexpected block after clear")
	}
}

func TestBillingResponseIndicatesInsufficientTokens(t *testing.T) {
	t.Parallel()
	if !billingResponseIndicatesInsufficientTokens(400, `{"error":"Insufficient tokens"}`) {
		t.Fatal("expected 400 + insufficient")
	}
	if billingResponseIndicatesInsufficientTokens(400, `{"error":"bad request"}`) {
		t.Fatal("unexpected block for unrelated 400")
	}
}
