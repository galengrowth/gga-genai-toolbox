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
Minimal accepted schema:
```json
{
  "valid": true,
  "claims": { "sub": "user-123", "email": "user@example.com" }
}
```
If `valid` is `false`, you may include an `error` field:
```json
{ "valid": false, "error": "expired" }
```

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
- Returned `claims` map is optional; if absent, auth still considered successful if `valid` is true.

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
