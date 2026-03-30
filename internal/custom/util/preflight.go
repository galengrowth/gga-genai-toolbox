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
	"fmt"
	"net/http"

	"github.com/googleapis/genai-toolbox/internal/util"
)

// PerformPreflightCheck runs quota authorization when quotaEndpoint is configured in context.
// When the endpoint is absent, this is a no-op (aligned with util/quota.go: presence of endpoint drives checks).
func PerformPreflightCheck(ctx context.Context, toolName string) (bool, error) {
	if util.BillingInsufficientTokensBlocked(ctx) {
		return false, util.NewClientServerError(
			"billing reported insufficient tokens on a prior request; further tool calls are blocked until billing succeeds or the block expires",
			http.StatusTooManyRequests,
			nil,
		)
	}
	if util.QuotaEndpointFromContext(ctx) == "" {
		return true, nil
	}
	allowed, remaining, reason, qerr := util.CheckQuotaAndAuthorize(ctx, toolName, nil)
	if qerr != nil {
		return false, util.NewClientServerError(fmt.Sprintf("quota preflight failed: %s", qerr), http.StatusServiceUnavailable, qerr)
	}
	if !allowed {
		if reason == "" {
			reason = "row limit exceeded"
		}
		return false, util.NewClientServerError(fmt.Sprintf("quota denied: %s (remaining_rows=%d)", reason, remaining), http.StatusTooManyRequests, nil)
	}
	return true, nil
}
