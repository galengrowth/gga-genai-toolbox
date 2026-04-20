// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package util

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	tbutil "github.com/googleapis/mcp-toolbox/internal/util"
)

func TestPerformPreflightCheck_quotaAllowedClearsBillingBlock(t *testing.T) {
	t.Parallel()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("want POST, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"allowed": true, "reason": "OK"})
	}))
	defer ts.Close()

	ctx := context.Background()
	ctx = tbutil.WithJWTClaims(ctx, map[string]any{"sub": "preflight-test-sub"})
	ctx = tbutil.WithQuotaEndpoint(ctx, ts.URL)

	tbutil.SetBillingInsufficientTokensBlock(ctx)
	if !tbutil.BillingInsufficientTokensBlocked(ctx) {
		t.Fatal("setup: expected billing block")
	}

	ok, err := PerformPreflightCheck(ctx, "some_tool")
	if err != nil || !ok {
		t.Fatalf("PerformPreflightCheck: ok=%v err=%v", ok, err)
	}
	if tbutil.BillingInsufficientTokensBlocked(ctx) {
		t.Fatal("expected billing block cleared after successful quota preflight")
	}
}

func TestPerformPreflightCheck_billingBlockWithoutQuota(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ctx = tbutil.WithJWTClaims(ctx, map[string]any{"sub": "preflight-test-sub-no-quota"})
	tbutil.SetBillingInsufficientTokensBlock(ctx)

	ok, err := PerformPreflightCheck(ctx, "some_tool")
	if err == nil || ok {
		t.Fatalf("expected billing block error, ok=%v err=%v", ok, err)
	}
}
