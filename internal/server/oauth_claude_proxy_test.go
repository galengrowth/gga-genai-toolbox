// Copyright 2025 Galen Growth
//
// Licensed under the Apache License, Version 2.0 (the License);

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBuildClaudeOAuthProxy_Disabled(t *testing.T) {
	p, err := buildClaudeOAuthProxy(context.Background(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p != nil {
		t.Fatal("expected nil")
	}
}

func TestBuildClaudeOAuthProxy_ExplicitEndpoints(t *testing.T) {
	p, err := buildClaudeOAuthProxy(context.Background(), map[string]any{
		"oauthClaudeAuthProxy":            true,
		"oauthProxyAuthorizationEndpoint": "https://idp.example.com/authorize",
		"oauthProxyTokenEndpoint":         "https://idp.example.com/oauth/token",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.authorizeURL != "https://idp.example.com/authorize" || p.tokenURL != "https://idp.example.com/oauth/token" {
		t.Fatalf("got %+v", p)
	}
}

func TestClaudeOAuthProxy_AuthorizeRedirect(t *testing.T) {
	p := &claudeOAuthProxy{authorizeURL: "https://idp.example.com/authorize"}
	req := httptest.NewRequest(http.MethodGet, "/authorize?client_id=x&response_type=code", nil)
	w := httptest.NewRecorder()
	p.authorizeRedirect(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("status %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if loc != "https://idp.example.com/authorize?client_id=x&response_type=code" {
		t.Fatalf("Location: %q", loc)
	}
}

func TestFetchOIDCDiscovery(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(oidcDiscoveryDoc{
			AuthorizationEndpoint: "https://idp.example.com/authorize",
			TokenEndpoint:         "https://idp.example.com/token",
			RegistrationEndpoint:  "https://idp.example.com/register",
		})
	}))
	defer ts.Close()

	client := &http.Client{}
	doc, err := fetchOIDCDiscovery(context.Background(), client, ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	if doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" {
		t.Fatalf("doc: %+v", doc)
	}
}
