// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package util

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"time"
)

// When the async billing POST returns insufficient tokens (e.g. 400), subsequent tool
// invocations must fail until billing succeeds again or the block expires.
// This is in-process only (not suitable for multi-replica without shared store).

const billingInsufficientBlockTTL = 24 * time.Hour

type billingBlockEntry struct {
	until time.Time
}

var billingInsufficientBlocks sync.Map // key: caller key, value: billingBlockEntry

// billingBlockKeyFromParts builds the same caller key used by billingCallerKey, without a context.
// authHeader is the raw Authorization header value (optional); when sub/email are empty it is hashed
// for a stable key (same scheme as billingCallerKey).
func billingBlockKeyFromParts(sub, email, authHeader string) string {
	if sub != "" {
		return "sub:" + sub
	}
	if email != "" {
		return "email:" + email
	}
	if authHeader != "" {
		sum := sha256.Sum256([]byte(authHeader))
		return "auth:" + hex.EncodeToString(sum[:16])
	}
	return ""
}

func billingCallerKey(ctx context.Context) string {
	sub, email := UserInfoFromContext(ctx)
	return billingBlockKeyFromParts(sub, email, AuthorizationHeaderFromContext(ctx))
}

// SetBillingInsufficientTokensBlockForParts records an insufficient-token block for the same identity
// fields sent on the billing POST (sub, email, optional raw Authorization). Used from the async billing
// goroutine so the block key matches the request even after the original context is no longer valid.
func SetBillingInsufficientTokensBlockForParts(sub, email, authHeader string) {
	k := billingBlockKeyFromParts(sub, email, authHeader)
	if k == "" {
		return
	}
	billingInsufficientBlocks.Store(k, billingBlockEntry{until: time.Now().Add(billingInsufficientBlockTTL)})
}

// ClearBillingInsufficientTokensBlockForParts removes the block for the given identity parts.
func ClearBillingInsufficientTokensBlockForParts(sub, email, authHeader string) {
	k := billingBlockKeyFromParts(sub, email, authHeader)
	if k == "" {
		return
	}
	billingInsufficientBlocks.Delete(k)
}

// SetBillingInsufficientTokensBlock records that the billing usage POST reported insufficient tokens.
func SetBillingInsufficientTokensBlock(ctx context.Context) {
	sub, email := UserInfoFromContext(ctx)
	SetBillingInsufficientTokensBlockForParts(sub, email, AuthorizationHeaderFromContext(ctx))
}

// ClearBillingInsufficientTokensBlock removes the block after a successful billing POST (2xx).
func ClearBillingInsufficientTokensBlock(ctx context.Context) {
	sub, email := UserInfoFromContext(ctx)
	ClearBillingInsufficientTokensBlockForParts(sub, email, AuthorizationHeaderFromContext(ctx))
}

// BillingInsufficientTokensBlocked is true if a prior billing POST denied usage for this caller.
func BillingInsufficientTokensBlocked(ctx context.Context) bool {
	k := billingCallerKey(ctx)
	if k == "" {
		return false
	}
	v, ok := billingInsufficientBlocks.Load(k)
	if !ok {
		return false
	}
	ent, ok := v.(billingBlockEntry)
	if !ok {
		billingInsufficientBlocks.Delete(k)
		return false
	}
	if time.Now().After(ent.until) {
		billingInsufficientBlocks.Delete(k)
		return false
	}
	return true
}

func billingResponseIndicatesInsufficientTokens(statusCode int, body string) bool {
	if statusCode == http.StatusTooManyRequests || statusCode == http.StatusForbidden {
		return true
	}
	b := strings.ToLower(body)
	if strings.Contains(b, "insufficient") && (strings.Contains(b, "token") || strings.Contains(b, "quota") || strings.Contains(b, "credit")) {
		return true
	}
	// Billing APIs sometimes return 400 with {"error":"Insufficient tokens"}.
	return statusCode == http.StatusBadRequest && strings.Contains(b, "insufficient")
}
