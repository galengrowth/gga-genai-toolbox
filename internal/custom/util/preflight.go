// Copyright 2025 Galen Growth
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
	"net/http"

	"github.com/googleapis/mcp-toolbox/internal/util"
)

// PerformPreflightCheck runs quota authorization when quotaEndpoint is configured in context.
// When the endpoint is absent, this is a no-op (aligned with util/quota.go: presence of endpoint drives checks).
//
// Quota/authorize runs before the in-process billing insufficient-token block so upstream DB-backed
// policy (e.g. authorize returning allowed:true) can take effect without restarting MCP. When
// authorize allows, we clear any stale billing block; the block still applies when quotaEndpoint is unset.
func PerformPreflightCheck(ctx context.Context, toolName string) (bool, error) {
	if util.QuotaEndpointFromContext(ctx) != "" {
		allowed, _, _, qerr := util.CheckQuotaAndAuthorize(ctx, toolName, nil)
		if qerr != nil {
			return false, util.NewClientServerError("Usage limits could not be checked. Try again shortly.", http.StatusServiceUnavailable, nil)
		}
		if !allowed {
			return false, util.NewClientServerError("Query allowance exceeded. Reduce the result size or try again after reset.", http.StatusTooManyRequests, nil)
		}
		// Authorize upstream says OK — clear stale MCP-only billing block (see util/billing_tokens_block.go).
		util.ClearBillingInsufficientTokensBlock(ctx)
	}
	if util.BillingInsufficientTokensBlocked(ctx) {
		return false, util.NewClientServerError(
			"Your usage allowance is exhausted. Add credits or wait for it to reset.",
			http.StatusTooManyRequests,
			nil,
		)
	}
	return true, nil
}
