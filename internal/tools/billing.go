// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package tools

import (
	"fmt"
	"reflect"

	"github.com/googleapis/genai-toolbox/internal/util/parameters"
)

// maxBillingQueryLen limits the query string sent on billing POSTs (UTF-8 byte length).
const maxBillingQueryLen = 65536

// BillingRowCountFromResult approximates how many logical rows or records the tool returned.
// It is best-effort across tool types (SQL row slices, API envelopes, scalars).
func BillingRowCountFromResult(result any) int {
	if result == nil {
		return 0
	}
	v := reflect.ValueOf(result)
	switch v.Kind() {
	case reflect.Slice, reflect.Array:
		return v.Len()
	case reflect.Map:
		if m, ok := result.(map[string]any); ok {
			return billingRowCountFromStringKeyMap(m)
		}
		return 1
	case reflect.String:
		if v.Len() == 0 {
			return 0
		}
		return 1
	default:
		return 1
	}
}

func billingRowCountFromStringKeyMap(m map[string]any) int {
	if len(m) == 0 {
		return 0
	}
	for _, key := range []string{"rows", "data", "results", "Records", "records"} {
		if inner, ok := m[key]; ok && inner != nil {
			iv := reflect.ValueOf(inner)
			if iv.Kind() == reflect.Slice || iv.Kind() == reflect.Array {
				return iv.Len()
			}
		}
	}
	return 1
}

// BillingQueryFromToolInvocation returns the best-effort query text for billing:
// 1) common parameter names on the request (sql, query, statement, cypher, prompt);
// 2) otherwise, YAML Statement/Query from the tool config with template resolution when applicable.
func BillingQueryFromToolInvocation(tool Tool, params parameters.ParamValues) string {
	q := billingQueryFromParamsMap(params.AsMap())
	if q != "" {
		return truncateBillingQuery(q)
	}
	q = resolvedStatementFromToolConfig(tool, params.AsMap())
	return truncateBillingQuery(q)
}

func billingQueryFromParamsMap(pm map[string]any) string {
	for _, key := range []string{"sql", "query", "statement", "cypher", "prompt"} {
		if s, ok := paramAsString(pm[key]); ok && s != "" {
			return s
		}
	}
	return ""
}

func paramAsString(v any) (string, bool) {
	if v == nil {
		return "", false
	}
	switch t := v.(type) {
	case string:
		return t, true
	case fmt.Stringer:
		return t.String(), true
	default:
		return fmt.Sprint(t), true
	}
}

func derefReflect(v reflect.Value) reflect.Value {
	for v.Kind() == reflect.Ptr || v.Kind() == reflect.Interface {
		if v.IsNil() {
			return reflect.Value{}
		}
		v = v.Elem()
	}
	return v
}

func resolvedStatementFromToolConfig(tool Tool, paramsMap map[string]any) string {
	cfg := tool.ToConfig()
	if cfg == nil {
		return ""
	}
	v := derefReflect(reflect.ValueOf(cfg))
	if !v.IsValid() || v.Kind() != reflect.Struct {
		return ""
	}
	var statement string
	if s := v.FieldByName("Statement"); s.IsValid() && s.Kind() == reflect.String {
		statement = s.String()
	}
	if statement == "" {
		if q := v.FieldByName("Query"); q.IsValid() && q.Kind() == reflect.String {
			statement = q.String()
		}
	}
	if statement == "" {
		return ""
	}
	tpl := parameters.Parameters{}
	if tplField := v.FieldByName("TemplateParameters"); tplField.IsValid() {
		if tp, ok := tplField.Interface().(parameters.Parameters); ok {
			tpl = tp
		}
	}
	resolved, err := parameters.ResolveTemplateParams(tpl, statement, paramsMap)
	if err != nil {
		return statement
	}
	return resolved
}

func truncateBillingQuery(s string) string {
	if len(s) <= maxBillingQueryLen {
		return s
	}
	return s[:maxBillingQueryLen] + "...<truncated>"
}
