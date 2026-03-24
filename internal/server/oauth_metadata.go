// Copyright 2025 Galen Growth
//
// Licensed under the Apache License, Version 2.0 (the License);
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an AS IS BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/googleapis/genai-toolbox/internal/auth"
	"github.com/googleapis/genai-toolbox/internal/custom/auth/authzero"
)

// oauthProtectedResourceConfig holds RFC 9728 OAuth 2.0 Protected Resource Metadata
// for MCP / OAuth clients that discover authorization servers via /.well-known/oauth-protected-resource.
type oauthProtectedResourceConfig struct {
	Resource             string
	AuthorizationServers []string
	ScopesSupported      []string
}

func parseOAuthProtectedResourceMetadata(custom map[string]any, authServices map[string]auth.AuthService) (*oauthProtectedResourceConfig, error) {
	if custom == nil {
		return nil, nil
	}
	enabled, ok := boolFromAny(custom["oauthProtectedResourceMetadata"])
	if !ok || !enabled {
		return nil, nil
	}
	resource, _ := custom["oauthResource"].(string)
	resource = strings.TrimSpace(resource)
	if resource == "" {
		return nil, fmt.Errorf("custom.oauthProtectedResourceMetadata is true but custom.oauthResource is empty")
	}
	servers, err := parseAuthorizationServers(custom["oauthAuthorizationServers"])
	if err != nil {
		return nil, err
	}
	if len(servers) == 0 {
		servers = issuersFromAuthZeroServices(authServices)
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("custom.oauthAuthorizationServers is empty and no authzero services found to derive issuer URLs")
	}
	scopes, err := stringSliceFromAny(custom["oauthScopesSupported"])
	if err != nil {
		return nil, fmt.Errorf("custom.oauthScopesSupported: %w", err)
	}

	return &oauthProtectedResourceConfig{
		Resource:             resource,
		AuthorizationServers: servers,
		ScopesSupported:      scopes,
	}, nil
}

func boolFromAny(v any) (bool, bool) {
	switch x := v.(type) {
	case bool:
		return x, true
	case string:
		switch strings.ToLower(strings.TrimSpace(x)) {
		case "true", "1", "yes":
			return true, true
		case "false", "0", "no":
			return false, true
		default:
			return false, false
		}
	case int:
		return x != 0, true
	default:
		return false, false
	}
}

func parseAuthorizationServers(v any) ([]string, error) {
	if v == nil {
		return nil, nil
	}
	switch x := v.(type) {
	case string:
		s := strings.TrimSpace(x)
		if s == "" {
			return nil, nil
		}
		return []string{s}, nil
	case []string:
		return trimNonEmpty(x), nil
	case []any:
		var out []string
		for _, item := range x {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("oauthAuthorizationServers must be a list of strings")
			}
			s = strings.TrimSpace(s)
			if s != "" {
				out = append(out, s)
			}
		}
		return out, nil
	default:
		return nil, fmt.Errorf("oauthAuthorizationServers must be a string or list of strings")
	}
}

func stringSliceFromAny(v any) ([]string, error) {
	if v == nil {
		return nil, nil
	}
	switch x := v.(type) {
	case []string:
		return trimNonEmpty(x), nil
	case []any:
		var out []string
		for _, item := range x {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("expected list of strings")
			}
			if t := strings.TrimSpace(s); t != "" {
				out = append(out, t)
			}
		}
		return out, nil
	default:
		return nil, fmt.Errorf("expected list of strings or omit the field")
	}
}

func trimNonEmpty(ss []string) []string {
	var out []string
	for _, s := range ss {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func issuersFromAuthZeroServices(authServices map[string]auth.AuthService) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, svc := range authServices {
		az, ok := svc.(*authzero.AuthService)
		if !ok {
			continue
		}
		iss := "https://" + az.Domain + "/"
		if _, dup := seen[iss]; dup {
			continue
		}
		seen[iss] = struct{}{}
		out = append(out, iss)
	}
	return out
}

func serveOAuthProtectedResource(prm *oauthProtectedResourceConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if prm == nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		doc := map[string]any{
			"resource":                 prm.Resource,
			"authorization_servers":    prm.AuthorizationServers,
			"bearer_methods_supported": []string{"header"},
		}
		if len(prm.ScopesSupported) > 0 {
			doc["scopes_supported"] = prm.ScopesSupported
		}
		_ = json.NewEncoder(w).Encode(doc)
	}
}

// metadataDocumentURL builds the absolute URL for this host's PRM document (RFC 9728).
func metadataDocumentURL(r *http.Request) string {
	proto := r.Header.Get("X-Forwarded-Proto")
	if proto == "" {
		if r.TLS == nil {
			proto = "http"
		} else {
			proto = "https"
		}
	}
	return fmt.Sprintf("%s://%s/.well-known/oauth-protected-resource", proto, r.Host)
}

func (s *Server) setWWWAuthenticateForUnauthorized(w http.ResponseWriter, r *http.Request) {
	if s.oauthPRM == nil {
		return
	}
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata=%q`, metadataDocumentURL(r)))
}
