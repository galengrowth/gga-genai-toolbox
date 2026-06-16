// Copyright 2026 Galen Growth
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

package server

import (
	"fmt"
	"net/http"
	"strings"
)

// openaiAppsChallenge serves the OpenAI ChatGPT Apps domain verification token at
// GET /.well-known/openai-apps-challenge (plain text, HTTP 200).
type openaiAppsChallenge struct {
	token string
}

func buildOpenAIAppsChallenge(custom map[string]any) (*openaiAppsChallenge, error) {
	if custom == nil {
		return nil, nil
	}
	ok, valid := boolFromAny(custom["openaiAppsDomainVerification"])
	if !valid || !ok {
		return nil, nil
	}
	token := strings.TrimSpace(strFromAny(custom["openaiAppsVerificationToken"]))
	if token == "" {
		return nil, fmt.Errorf("openaiAppsDomainVerification is true: openaiAppsVerificationToken must be set")
	}
	return &openaiAppsChallenge{token: token}, nil
}

func (c *openaiAppsChallenge) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(c.token))
}
