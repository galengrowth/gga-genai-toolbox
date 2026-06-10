// Copyright 2026 Galen Growth
//
// Licensed under the Apache License, Version 2.0 (the "License");

package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBuildOpenAIAppsChallenge_Disabled(t *testing.T) {
	t.Parallel()
	c, err := buildOpenAIAppsChallenge(nil)
	if err != nil {
		t.Fatal(err)
	}
	if c != nil {
		t.Fatal("expected nil when custom is nil")
	}

	c, err = buildOpenAIAppsChallenge(map[string]any{"openaiAppsDomainVerification": false})
	if err != nil {
		t.Fatal(err)
	}
	if c != nil {
		t.Fatal("expected nil when flag is false")
	}
}

func TestBuildOpenAIAppsChallenge_MissingToken(t *testing.T) {
	t.Parallel()
	_, err := buildOpenAIAppsChallenge(map[string]any{"openaiAppsDomainVerification": true})
	if err == nil {
		t.Fatal("expected error when token is empty")
	}
}

func TestBuildOpenAIAppsChallenge_Enabled(t *testing.T) {
	t.Parallel()
	c, err := buildOpenAIAppsChallenge(map[string]any{
		"openaiAppsDomainVerification": true,
		"openaiAppsVerificationToken":  "test-token-abc",
	})
	if err != nil {
		t.Fatal(err)
	}
	if c == nil || c.token != "test-token-abc" {
		t.Fatalf("got %+v", c)
	}
}

func TestOpenAIAppsChallenge_Serve(t *testing.T) {
	t.Parallel()
	c := &openaiAppsChallenge{token: "verify-me"}
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openai-apps-challenge", nil)
	w := httptest.NewRecorder()
	c.serve(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Fatalf("Content-Type: %q", ct)
	}
	if body := w.Body.String(); body != "verify-me" {
		t.Fatalf("body: %q", body)
	}
}
