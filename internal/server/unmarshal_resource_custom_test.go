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

package server

import (
	"context"
	"testing"

	_ "github.com/googleapis/mcp-toolbox/internal/sources/mysql"
)

func TestUnmarshalResourceConfig_skipsKindCustom(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	raw := []byte(`kind: custom
billingEndpoint: https://billing.example
---
kind: source
name: s1
type: mysql
host: 127.0.0.1
port: "3306"
database: db
user: u
password: p
`)
	src, auth, emb, tools, sets, prompts, err := UnmarshalResourceConfig(ctx, raw)
	if err != nil {
		t.Fatalf("UnmarshalResourceConfig: %v", err)
	}
	if len(src) != 1 || src["s1"] == nil {
		t.Fatalf("expected one source s1, got %#v", src)
	}
	if len(auth) != 0 || len(emb) != 0 || len(tools) != 0 || len(sets) != 0 || len(prompts) != 0 {
		t.Fatalf("expected only source populated, got auth=%d emb=%d tools=%d sets=%d prompts=%d",
			len(auth), len(emb), len(tools), len(sets), len(prompts))
	}
}
