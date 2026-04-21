// Copyright 2025 Galen Growth
//
// Licensed under the Apache License, Version 2.0 (the License);
// you may not use this file except in compliance with the License.
//
// Workaround for Claude.ai MCP OAuth: the web client appends /authorize, /token, and /register
// to the MCP server origin instead of using authorization_endpoint / token_endpoint from metadata
// (see https://github.com/anthropics/claude-ai-mcp/issues/82). These handlers forward to the
// real authorization server (e.g. Auth0).

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/googleapis/mcp-toolbox/internal/auth"
	"github.com/googleapis/mcp-toolbox/internal/custom/auth/authzero"
)

// claudeOAuthProxy forwards browser / backend OAuth requests to the configured IdP.
type claudeOAuthProxy struct {
	authorizeURL    string
	tokenURL        string
	registrationURL string
	client          *http.Client
}

type oidcDiscoveryDoc struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	RegistrationEndpoint  string `json:"registration_endpoint"`
}

func buildClaudeOAuthProxy(ctx context.Context, custom map[string]any, authServices map[string]auth.AuthService) (*claudeOAuthProxy, error) {
	if custom == nil {
		return nil, nil
	}
	ok, valid := boolFromAny(custom["oauthClaudeAuthProxy"])
	if !valid || !ok {
		return nil, nil
	}

	client := &http.Client{Timeout: 60 * time.Second}

	authz := strings.TrimSpace(strFromAny(custom["oauthProxyAuthorizationEndpoint"]))
	token := strings.TrimSpace(strFromAny(custom["oauthProxyTokenEndpoint"]))
	reg := strings.TrimSpace(strFromAny(custom["oauthProxyRegistrationEndpoint"]))

	needDiscovery := authz == "" || token == ""
	var doc *oidcDiscoveryDoc
	var err error
	if needDiscovery {
		issuer := strings.TrimSpace(strFromAny(custom["oauthProxyIssuer"]))
		if issuer == "" {
			issuer = firstAuthZeroIssuerBase(authServices)
		}
		if issuer == "" {
			return nil, fmt.Errorf("oauthClaudeAuthProxy is true: set oauthProxyIssuer or oauthProxyAuthorizationEndpoint+oauthProxyTokenEndpoint, or configure authzero")
		}
		doc, err = fetchOIDCDiscovery(ctx, client, issuer)
		if err != nil {
			return nil, fmt.Errorf("oauth Claude proxy: OIDC discovery: %w", err)
		}
		if authz == "" {
			authz = strings.TrimSpace(doc.AuthorizationEndpoint)
		}
		if token == "" {
			token = strings.TrimSpace(doc.TokenEndpoint)
		}
		if reg == "" {
			reg = strings.TrimSpace(doc.RegistrationEndpoint)
		}
	} else if reg == "" {
		issuer := strings.TrimSpace(strFromAny(custom["oauthProxyIssuer"]))
		if issuer == "" {
			issuer = firstAuthZeroIssuerBase(authServices)
		}
		if issuer != "" {
			doc, err = fetchOIDCDiscovery(ctx, client, issuer)
			if err == nil && doc != nil {
				reg = strings.TrimSpace(doc.RegistrationEndpoint)
			}
		}
	}

	if authz == "" {
		return nil, fmt.Errorf("oauthClaudeAuthProxy: missing authorization endpoint (discovery failed or oauthProxyAuthorizationEndpoint empty)")
	}
	if token == "" {
		return nil, fmt.Errorf("oauthClaudeAuthProxy: missing token endpoint (discovery failed or oauthProxyTokenEndpoint empty)")
	}

	return &claudeOAuthProxy{
		authorizeURL:    authz,
		tokenURL:        token,
		registrationURL: reg,
		client:          client,
	}, nil
}

func strFromAny(v any) string {
	if v == nil {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

func firstAuthZeroIssuerBase(authServices map[string]auth.AuthService) string {
	for _, svc := range authServices {
		az, ok := svc.(*authzero.AuthService)
		if !ok {
			continue
		}
		return "https://" + az.Domain
	}
	return ""
}

func fetchOIDCDiscovery(ctx context.Context, client *http.Client, issuerBase string) (*oidcDiscoveryDoc, error) {
	issuerBase = strings.TrimSuffix(strings.TrimSpace(issuerBase), "/")
	if issuerBase == "" {
		return nil, fmt.Errorf("empty issuer")
	}
	url := issuerBase + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	var doc oidcDiscoveryDoc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

func (p *claudeOAuthProxy) authorizeRedirect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	dest := p.authorizeURL
	if q := r.URL.RawQuery; q != "" {
		if strings.Contains(dest, "?") {
			dest += "&" + q
		} else {
			dest += "?" + q
		}
	}
	http.Redirect(w, r, dest, http.StatusFound)
}

func (p *claudeOAuthProxy) proxyToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	p.proxyPOST(w, r, p.tokenURL)
}

func (p *claudeOAuthProxy) proxyRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if p.registrationURL == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotImplemented)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "registration_endpoint_not_configured",
			"error_description": "No registration_endpoint in OIDC discovery; Auth0 may require a plan that exposes Dynamic Client Registration, or set oauthProxyRegistrationEndpoint in tools.yaml",
		})
		return
	}
	p.proxyPOST(w, r, p.registrationURL)
}

func (p *claudeOAuthProxy) proxyPOST(w http.ResponseWriter, r *http.Request, targetURL string) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for _, h := range []string{"Content-Type", "Accept", "Authorization"} {
		if v := r.Header.Get(h); v != "" {
			req.Header.Set(h, v)
		}
	}

	resp, err := p.client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for _, k := range []string{"Content-Type", "Cache-Control", "Pragma"} {
		if v := resp.Header.Get(k); v != "" {
			w.Header().Set(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}
