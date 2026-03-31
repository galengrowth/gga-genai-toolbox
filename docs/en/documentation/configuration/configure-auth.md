# Configure Authentication Services

This guide explains how to configure the built‑in authentication kinds:

- `google` (Google OAuth / identity tokens)
- `authzero` (JWT validation using Auth0 / generic OIDC JWKS)
- `hta` (Custom POST validator – external service determines token validity)

## 1. AuthZero (kind: authzero)
Use this when you have a standard OIDC / Auth0 issuer exposing a JWKS endpoint.

```yaml
authServices:
  my_authzero:
    kind: authzero
    domain: ${AUTHZERO_DOMAIN}        # e.g. dev-tenant.us.auth0.com
    audience: ${AUTHZERO_AUDIENCE}    # API audience / identifier
```
The server will:
1. Download JWKS from `https://<domain>/.well-known/jwks.json` (cached & periodically refreshed).
2. Validate the Bearer token signature and standard claims.
3. Enforce issuer (`iss`) and audience (`aud`).
4. Expose the decoded claims to downstream billing / quota logic.

### OAuth Protected Resource Metadata (RFC 9728)

For MCP clients that discover authorization via `/.well-known/oauth-protected-resource`, enable this under the top-level `custom:` block in `tools.yaml`:

```yaml
custom:
  oauthProtectedResourceMetadata: true
  oauthResource: "https://your-public-host/mcp"   # protected resource identifier (RFC 9728 `resource`; can be origin or /mcp URL)
  # oauthAuthorizationServers:                    # optional: omit to derive from authzero issuer(s)
  #   - "https://your-tenant.us.auth0.com/"
  # oauthScopesSupported: ["mcp:read", "mcp:tools"]   # optional; RFC 9728 scopes_supported
  # oauthResourceDocumentation: "https://your-public-host/docs"   # optional; RFC 9728 resource_documentation
  # oauthResourceName: "My MCP (dev)"            # optional; emitted as resource_name (non-standard, for display)
```

When enabled, the server serves `GET /.well-known/oauth-protected-resource` and adds a `WWW-Authenticate` hint on MCP `401` responses pointing at that document. If `oauthAuthorizationServers` is omitted, issuers are derived from configured `authzero` services (`https://<domain>/`).

### Claude.ai OAuth proxy (`/authorize`, `/token`, `/register`)

Claude.ai’s web MCP client may call `GET /authorize`, `POST /token`, and `POST /register` on **your MCP host** instead of your IdP (e.g. Auth0), even when metadata points elsewhere ([upstream issue](https://github.com/anthropics/claude-ai-mcp/issues/82)). Enable this workaround under `custom:`:

```yaml
custom:
  oauthClaudeAuthProxy: true
  # Issuer base URL used to fetch /.well-known/openid-configuration (omit if you have authzero — it will be derived)
  # oauthProxyIssuer: "https://your-tenant.us.auth0.com"
  # Or set endpoints explicitly instead of discovery:
  # oauthProxyAuthorizationEndpoint: "https://your-tenant.us.auth0.com/authorize"
  # oauthProxyTokenEndpoint: "https://your-tenant.us.auth0.com/oauth/token"
  # oauthProxyRegistrationEndpoint: ""   # optional; from discovery if omitted
```

When `oauthClaudeAuthProxy` is true, Toolbox discovers `authorization_endpoint`, `token_endpoint`, and `registration_endpoint` from OIDC metadata (unless overridden) and forwards those paths on your server to the real IdP.

**If `GET /authorize` returns 404** while `GET /.well-known/oauth-protected-resource` works, the request is usually **not reaching Toolbox**: many ingresses or API gateways only forward `/mcp` to the app. You must route **at least** these prefixes to the same Toolbox upstream as `/mcp`:

- `/authorize`, `/token`, `/register`
- `/.well-known/` (for PRM and OIDC-style discovery)
- optional: `/oauthproxy/ping` — returns `{"claude_oauth_proxy":true}` when the proxy is enabled (use this to verify routing)

Example (nginx): forward the whole host to Toolbox, or add explicit `location` blocks for the paths above.

Example (Kubernetes Ingress): use `path: /` with `pathType: Prefix` for the Toolbox service, or add multiple path rules so `/authorize` is not dropped by a `/mcp`-only rule.

## 2. Google (kind: google)
Example (simplified – fill in fields required by Google config):
```yaml
authServices:
  google_identity:
    kind: google
    # other google-specific fields...
```

## 3. Custom External Validator (kind: hta)
Use this when you have your own authorization microservice. Toolbox will POST the bearer token to your endpoint and rely entirely on its response.

### Expected Request
```
POST <authEndPoint>
Content-Type: application/json

{"token":"<bearer-token>"}
```

### Expected Response (JSON)
The entire response body is treated as the claims map. For example:
```json
{
  "authorized": true,
  "sub": "user-123",
  "email": "user@example.com"
}
```
- Success: HTTP 2xx status with any valid JSON.
- Failure: HTTP non-2xx status (e.g., 401 for invalid token).

### Example Configuration
```yaml
authServices:
  custom_post_validator:
    kind: hta
    authEndPoint: https://auth.internal.example.com/validate
    timeout: 5s              # optional (defaults to 5s)
```
Environment-variable form with defaults (as shown in prebuilt configs):
```yaml
authServices:
  custom_post_validator:
    kind: hta
    authEndPoint: ${HTA_AUTH_ENDPOINT:https://example.com/auth/validate}
    timeout: ${HTA_AUTH_TIMEOUT:5s}
```

### Behavior Summary
- The token is only sent inside the JSON body (not forwarded headers apart from Content-Type/Accept).
- Non-2xx response status codes are treated as authentication failure.
- Response body is truncated in logs for safety (currently 300 chars where logged).
- The entire response JSON is used as the claims map for downstream processing.

### Design Considerations
| Aspect | Rationale |
| ------ | --------- |
| POST with JSON | Avoid logs / proxies unintentionally capturing Authorization header. |
| Timeout (default 5s) | Prevent hanging tool requests due to external dependency slowness. |
| Claims passthrough | Enables quota/billing enrichment (e.g., `sub`, `email`). |
| Minimal schema | Keeps external service contract easy to evolve. |

### Extending
Future enhancements you can add:
- mTLS between Toolbox and the auth endpoint.
- Caching positive validations for short TTL to reduce load.
- Structured metrics (success/failure/latency histograms).
- Retry w/ backoff for transient 5xx responses (currently a single attempt).

## Selecting an Auth Kind
| Scenario | Recommended Kind |
| -------- | ---------------- |
| Standard OIDC (Auth0 / Okta style) | `authzero` |
| Internal custom policy engine | `hta` |
| Google Cloud identity token verification | `google` |

## Using Claims in Tools
Downstream logic (billing/quota) automatically reads `sub` and `email` when present. Your external validator can return any additional keys, which will be included in the generic claims map.

## Troubleshooting
| Symptom | Likely Cause | Action |
| ------- | ------------ | ------ |
| 401 / auth failure with kind `authzero` | Audience or issuer mismatch | Check `aud` claim & config `audience`; ensure issuer ends with `/`. |
| 401 with kind `hta` and message `auth endpoint rejected token` | External service returned non-2xx | Inspect external service logs; verify URL & network access. |
| Timeout error on `hta` | Slow external service | Increase `timeout` or optimize service response time. |
| Missing `email` in claims | Upstream identity provider not including it | Adjust upstream token scope/claims or have `hta` service enrich it. |

## Security Notes
- Ensure `authEndPoint` uses HTTPS.
- Avoid logging full tokens in your external service.
- Consider rate limiting / abuse protection on the custom validator.
- If adding caching, include token hash + expiry, not full token plain text.

---
This document will evolve as additional auth kinds or features are added.
