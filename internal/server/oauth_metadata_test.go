// Copyright 2025 Galen Growth
//
// Licensed under the Apache License, Version 2.0 (the License);
// you may not use this file except in compliance with the License.

package server

import (
	"net/http"
	"testing"

	"github.com/googleapis/mcp-toolbox/internal/auth"
)

func TestParseOAuthProtectedResourceMetadata_Disabled(t *testing.T) {
	prm, err := parseOAuthProtectedResourceMetadata(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if prm != nil {
		t.Fatalf("expected nil when disabled, got %+v", prm)
	}
	prm, err = parseOAuthProtectedResourceMetadata(map[string]any{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if prm != nil {
		t.Fatal("expected nil")
	}
}

func TestParseOAuthProtectedResourceMetadata_ExplicitServers(t *testing.T) {
	prm, err := parseOAuthProtectedResourceMetadata(map[string]any{
		"oauthProtectedResourceMetadata": true,
		"oauthResource":                  "https://api.example.com/mcp",
		"oauthAuthorizationServers":      []any{"https://issuer.example.com/"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if prm.Resource != "https://api.example.com/mcp" {
		t.Fatalf("resource: got %q", prm.Resource)
	}
	if len(prm.AuthorizationServers) != 1 || prm.AuthorizationServers[0] != "https://issuer.example.com/" {
		t.Fatalf("servers: %+v", prm.AuthorizationServers)
	}
}

func TestParseOAuthProtectedResourceMetadata_OptionalDocsAndName(t *testing.T) {
	prm, err := parseOAuthProtectedResourceMetadata(map[string]any{
		"oauthProtectedResourceMetadata": true,
		"oauthResource":                  "https://api.example.com",
		"oauthAuthorizationServers":      []any{"https://issuer.example.com/"},
		"oauthScopesSupported":           []any{"mcp:read", "mcp:tools"},
		"oauthResourceDocumentation":   "https://api.example.com/docs",
		"oauthResourceName":            "Example MCP",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if prm.ResourceDocumentation != "https://api.example.com/docs" || prm.ResourceName != "Example MCP" {
		t.Fatalf("got doc=%q name=%q", prm.ResourceDocumentation, prm.ResourceName)
	}
	if len(prm.ScopesSupported) != 2 {
		t.Fatalf("scopes: %+v", prm.ScopesSupported)
	}
}

func TestParseOAuthProtectedResourceMetadata_MissingResource(t *testing.T) {
	_, err := parseOAuthProtectedResourceMetadata(map[string]any{
		"oauthProtectedResourceMetadata": true,
	}, nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestParseOAuthProtectedResourceMetadata_NoServersNoAuth(t *testing.T) {
	_, err := parseOAuthProtectedResourceMetadata(map[string]any{
		"oauthProtectedResourceMetadata": true,
		"oauthResource":                  "https://api.example.com/mcp",
	}, map[string]auth.AuthService{})
	if err == nil {
		t.Fatal("expected error when no authorization servers")
	}
}

func TestMetadataDocumentURL(t *testing.T) {
	req := mustReq(t, "http", "mcp.example.com")
	u := metadataDocumentURL(req)
	if u != "http://mcp.example.com/.well-known/oauth-protected-resource" {
		t.Fatalf("got %q", u)
	}
}

func TestMetadataDocumentURL_ForwardedProto(t *testing.T) {
	req := mustReq(t, "http", "mcp.example.com")
	req.Header.Set("X-Forwarded-Proto", "https")
	u := metadataDocumentURL(req)
	if u != "https://mcp.example.com/.well-known/oauth-protected-resource" {
		t.Fatalf("got %q", u)
	}
}

func mustReq(t *testing.T, scheme, host string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, scheme+"://"+host+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}
