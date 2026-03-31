// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package tools

import (
	"context"
	"errors"
	"testing"

	"github.com/googleapis/genai-toolbox/internal/embeddingmodels"
	"github.com/googleapis/genai-toolbox/internal/sources"
	"github.com/googleapis/genai-toolbox/internal/util"
	"github.com/googleapis/genai-toolbox/internal/util/parameters"
)

func TestBillingRowCountFromResult(t *testing.T) {
	t.Parallel()
	if n := BillingRowCountFromResult(nil); n != 0 {
		t.Fatalf("nil: got %d", n)
	}
	if n := BillingRowCountFromResult([]any{1, 2, 3}); n != 3 {
		t.Fatalf("slice: got %d", n)
	}
	if n := BillingRowCountFromResult(map[string]any{"rows": []any{"a", "b"}}); n != 2 {
		t.Fatalf("rows envelope: got %d", n)
	}
	if n := BillingRowCountFromResult(map[string]any{"k": "v"}); n != 1 {
		t.Fatalf("flat map: got %d", n)
	}
	if n := BillingRowCountFromResult("x"); n != 1 {
		t.Fatalf("string: got %d", n)
	}
	if n := BillingRowCountFromResult(""); n != 0 {
		t.Fatalf("empty string: got %d", n)
	}
}

type billingTestCfg struct {
	Statement          string
	TemplateParameters parameters.Parameters
}

func (billingTestCfg) ToolConfigType() string { return "billing-test" }

func (billingTestCfg) Initialize(map[string]sources.Source) (Tool, error) {
	return nil, errors.New("not used in test")
}

type billingMockTool struct {
	cfg billingTestCfg
}

func (m billingMockTool) Invoke(context.Context, SourceProvider, parameters.ParamValues, AccessToken) (any, util.ToolboxError) {
	return nil, nil
}

func (m billingMockTool) EmbedParams(context.Context, parameters.ParamValues, map[string]embeddingmodels.EmbeddingModel) (parameters.ParamValues, error) {
	return nil, nil
}

func (m billingMockTool) Manifest() Manifest { return Manifest{} }

func (m billingMockTool) McpManifest() McpManifest { return McpManifest{} }

func (m billingMockTool) Authorized([]string) bool { return true }

func (m billingMockTool) RequiresClientAuthorization(SourceProvider) (bool, error) {
	return false, nil
}

func (m billingMockTool) ToConfig() ToolConfig { return m.cfg }

func (m billingMockTool) GetAuthTokenHeaderName(SourceProvider) (string, error) {
	return "Authorization", nil
}

func (m billingMockTool) GetParameters() parameters.Parameters { return nil }

func TestBillingQueryFromToolInvocation_paramSQL(t *testing.T) {
	t.Parallel()
	tool := billingMockTool{}
	pv := parameters.ParamValues{{Name: "sql", Value: "SELECT 1"}}
	if q := BillingQueryFromToolInvocation(tool, pv); q != "SELECT 1" {
		t.Fatalf("got %q", q)
	}
}

func TestBillingQueryFromToolInvocation_configStatement(t *testing.T) {
	t.Parallel()
	tool := billingMockTool{cfg: billingTestCfg{Statement: "SELECT 1"}}
	pv := parameters.ParamValues{}
	if q := BillingQueryFromToolInvocation(tool, pv); q != "SELECT 1" {
		t.Fatalf("got %q", q)
	}
}
