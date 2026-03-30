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

func billingCallerKey(ctx context.Context) string {
	sub, email := UserInfoFromContext(ctx)
	if sub != "" {
		return "sub:" + sub
	}
	if email != "" {
		return "email:" + email
	}
	if auth := AuthorizationHeaderFromContext(ctx); auth != "" {
		sum := sha256.Sum256([]byte(auth))
		return "auth:" + hex.EncodeToString(sum[:16])
	}
	return ""
}

// SetBillingInsufficientTokensBlock records that the billing usage POST reported insufficient tokens.
func SetBillingInsufficientTokensBlock(ctx context.Context) {
	k := billingCallerKey(ctx)
	if k == "" {
		return
	}
	billingInsufficientBlocks.Store(k, billingBlockEntry{until: time.Now().Add(billingInsufficientBlockTTL)})
}

// ClearBillingInsufficientTokensBlock removes the block after a successful billing POST (2xx).
func ClearBillingInsufficientTokensBlock(ctx context.Context) {
	k := billingCallerKey(ctx)
	if k == "" {
		return
	}
	billingInsufficientBlocks.Delete(k)
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
