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

	"github.com/googleapis/genai-toolbox/internal/util"
)

// PerformPreflightCheck performs custom preflight checks like quota enforcement.
func PerformPreflightCheck(ctx context.Context, toolName string) (bool, error) {
	// Quota preflight: enforce only when both endpoint is configured and enforcement is enabled
	if qe := util.QuotaEndpointFromContext(ctx); qe != "" {
		if enforce, ok := util.QuotaEnforcementFromContext(ctx); ok && enforce {
			allowed, _, _, qerr := util.CheckQuotaAndAuthorize(ctx, toolName, nil)
			if qerr != nil {
				return false, fmt.Errorf("quota preflight failed: %s", qerr)
			}
			if !allowed {
				return false, fmt.Errorf("insufficient tokens")
			}
		}
	}
	return true, nil
}
