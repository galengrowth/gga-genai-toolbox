# Fork documentation (custom implementation)

This repository tracks upstream **[googleapis/mcp-toolbox](https://github.com/googleapis/mcp-toolbox)** (Go module `github.com/googleapis/mcp-toolbox`; development also appears under **[genai-toolbox](https://github.com/googleapis/genai-toolbox)**) with **Galen Growth / HealthTech Alpha** additions: billing and quota integration, OAuth PRM and Claude OAuth proxy, Auth0-style MCP auth (`authzero`), MySQL SQL guardrails, and related server hooks.

This is **fork-specific documentation**. It is **not** the official Google MCP Toolbox manual.

**Merging upstream later?** Use **[§ Re-syncing with upstream](#re-syncing-with-upstream-main)** as the step-by-step guide (git, conflict order, tests, doc updates).

---

## Where custom code lives

| Path | Purpose |
|------|---------|
| `internal/custom/util/` | Preflight helpers, billing/quota context enrichment, **`ValidateSQLForDatabase`** (MySQL), SQL tests |
| `internal/custom/auth/authzero/` | Auth0 JWT validation + **`mcpEnabled`** gate for MCP |
| `internal/custom/auth/hta/` | HTA-specific auth helpers (if used) |
| `internal/sources/mysql/mysql.go` | **Single choke point** for MySQL SQL validation: `RunSQL` calls `customutil.ValidateSQLForDatabase` before `QueryContext` |

Merge-friendly practice: keep **business logic** in `internal/custom/**` and **thin** call sites in `internal/server/**` / `internal/util/**` where upstream also changes often. See `internal/custom/README.md` for conflict-minimization tips.

---

## `custom:` keys in `tools.yaml` (or equivalent)

Server config may include fork settings **outside** the upstream core schema. Values are read in `internal/server/server.go` and related modules. You can express them in either form (multiple YAML documents are shallow-merged):

- **Nested (classic):** a top-level `custom:` map.
- **Flat (v2-style):** its own document with `kind: custom` and the **same keys as top-level siblings** (no `custom:` wrapper), consistent with `kind: source` / `kind: tool` / etc.

Parsing is implemented in `cmd/internal/config.go` (`extractCustomFromYAML`). Resource unmarshalling in `internal/server/config.go` **skips** `kind: custom` documents (they have no `name`); fork settings are merged only via `extractCustomFromYAML` before `UnmarshalResourceConfig` runs.

**If billing/quota HTTP stops after you comment URLs out but you still see outbound traffic:** (1) On startup, check logs for `billing: billingEndpoint not set` and `quota: quotaEndpoint not set` — if you instead see “set”, another merged file or an uncommented key still supplies the URL. (2) **`oauthClaudeAuthProxy`** performs OIDC discovery to your Auth0 tenant at startup (`/.well-known/openid-configuration`); that is **not** billing/quota. (3) Merging multiple YAML files **does not remove** keys omitted from a later file; an earlier file’s `billingEndpoint` would still apply unless you override or stop loading that file.

### Billing

| Key | Type | Purpose |
|-----|------|--------|
| **`billingEndpoint`** | string (URL) | JSON **POST** target for **usage / billing** events after a **successful** tool invocation. Payload includes `user_sub`, `user_email`, `tool`, `row_count`, `query`, `request_id`, `timestamp`. The client **`Authorization`** header is forwarded when present. |
| **`requireBillingPost`** | bool (or string `"true"` / int `1`) | Does **not** control whether POSTs are sent when `billingEndpoint` is set; POSTs are sent when the URL is configured. This flag controls **severity of logging** when the billing HTTP call fails (e.g. transport error or non-2xx): stricter **error**-level logs when `true`, **warn**-level when unset/false. |

#### Billing payload: `query` and `row_count` (implementation detail)

The billing POST is built in **`internal/util/billing.go`** (`BillingInfo`). The **`query`** string is produced by **`internal/tools/billing.go`** → **`BillingQueryFromToolInvocation`**, in this order:

1. **Explicit query-like parameters** on the tool request, if present: `sql`, `query`, `statement`, `cypher`, `prompt` (first non-empty wins).
2. Else the tool config **`Statement` / `Query`** field, with **template resolution** when the tool defines template parameters.
3. Else **compact JSON** of the **full resolved invocation parameter map** (so non-SQL tools still log useful context — e.g. `mysql-list-tables` with `output_format` and `table_names`).

**`row_count`** is a best-effort integer from **`BillingRowCountFromResult`** in the same package (slice length, common `{ "rows": [...] }` envelopes, etc.).

Strings are capped at **64KiB** UTF-8 bytes (`maxBillingQueryLen`).

**Impact:** Billing is **asynchronous** (goroutine). A billing failure **does not** roll back the tool result the client already received. If the billing API returns **insufficient tokens** (e.g. HTTP 400 with a matching body), the fork may **block further tool calls** for that caller until a **successful** billing response or a **time-based block expiry** (see `internal/util/billing_tokens_block.go`). When **`quotaEndpoint`** is configured, **quota/authorize runs first**; if authorize returns **`allowed: true`**, the toolbox **clears** that in-process block so your billing API’s DB-backed authorize path can recover **without restarting MCP**.

---

### Quota (authorize preflight)

| Key | Type | Purpose |
|-----|------|--------|
| **`quotaEndpoint`** | string (URL) | JSON **POST** target for **preflight authorization** before **`tool.Invoke`**. The request includes `user_sub`, `user_email`, `tool`, optional `requested_rows`, `request_id`, `timestamp`. **`Authorization`** is forwarded when present. |
| **`requireQuotaPreflight`** | bool | **Legacy / compatibility.** Quota preflight runs when **`quotaEndpoint`** is set; this flag is still parsed and stored on context but **does not** disable the quota call when omitted. |

**Expected response:** JSON with **`allowed`** (bool). HTTP **2xx** and **429** / **403** bodies are parsed when possible; **400** is treated as a denial path when the body indicates failure. Empty or malformed bodies are handled conservatively (see `internal/util/quota.go`).

**Impact:** If the quota service denies **or** returns an unexpected error, the **current** tool call **fails** (REST/MCP error) and **no** tool execution runs. This is **synchronous** and blocks the request. A successful **`allowed: true`** response also **clears** a stale billing insufficient-token block (see Billing impact above).

---

### OAuth (RFC 9728 PRM, Claude proxy)

| Key | Type | Purpose |
|-----|------|--------|
| **`oauthProtectedResourceMetadata`** | bool | Enables **`/.well-known/oauth-protected-resource`** (RFC 9728) for MCP OAuth discovery. |
| **`oauthResource`** | string (HTTPS URL) | **Required** when PRM is enabled: public resource identifier for this MCP server. |
| **`oauthAuthorizationServers`** | array of strings | Issuer URLs. If empty, issuers may be derived from **`authzero`** auth services. |
| **`oauthScopesSupported`** | array of strings | Scopes advertised in PRM. |
| **`oauthResourceDocumentation`** | string | Optional documentation URL. |
| **`oauthResourceName`** | string | Optional display name. |
| **`oauthClaudeAuthProxy`** | bool | Enables a **proxy** so Claude.ai can call `/authorize`, `/token`, `/register` on the toolbox origin; forwards to Auth0 (or configured endpoints). |
| **`oauthProxyIssuer`** | string | OIDC issuer for discovery when proxy endpoints are not set explicitly. |
| **`oauthProxyAuthorizationEndpoint`**, **`oauthProxyTokenEndpoint`**, **`oauthProxyRegistrationEndpoint`** | strings | Optional explicit IdP endpoints for the Claude proxy. |

**CLI / env:** **`--toolbox-url`** or **`TOOLBOX_URL`** should be the **public HTTPS base** of this server when MCP OAuth / PRM is used (see `cmd/root.go` validation).

**Connectors (ChatGPT, Claude, etc.):** Use **OAuth** with a **user-defined / static Auth0 application** when the IdP does not offer RFC 7591 Dynamic Client Registration that the connector accepts. DCR is an **authorization-server** feature, not something the MCP host implements; see product docs for your connector.

---

### Debugging (dangerous)

| Key | Type | Purpose |
|-----|------|--------|
| **`debugLogAuthToken`** | bool | Logs **raw Bearer tokens** (high risk). **Disable in production.** |

---

## Auth services (`authServices`)

Fork **`kind: authzero`** supports:

- **`mcpEnabled`**: when `true`, MCP requests can be gated to require a valid JWT for that Auth0 API audience (see `internal/custom/auth/authzero/`).

Upstream **`authService`** kinds (e.g. generic) may coexist; see `internal/server/config.go` and auth registration.

| Field | Purpose |
|-------|--------|
| **`domain`** | Auth0 tenant URL; drives JWKS URL and expected token **`iss`**. |
| **`audience`** | API identifier; must match access token **`aud`**. |
| **`authorizationServer`** | **Required when `mcpEnabled: true`**. Issuer URL advertised in PRM (`authorization_servers`) via `prmHandler` in `internal/server/mcp.go`. Often same origin as `domain`. |
| **`mcpEnabled`** | When `true`, `mcpAuthMiddleware` in `internal/server/server.go` validates Bearer JWT on all `/mcp` traffic. |
| **`scopesRequired`** | Optional; if set, token **`scope`** must include every listed scope (`ValidateMCPAuth`). |
| **`allowedAlgs`**, **`leeway`** | JWT algorithm allowlist and clock skew (see `authzero.go`). |

**Config validation:** `cmd/internal/config.go` rejects **more than one** `authService` with **`mcpEnabled: true`**.

### JWT signing keys (JWKS)—no YAML entry

Bearer JWTs are validated with **public keys** from your IdP’s **JWKS** document, not from `tools.yaml`.

- **authzero:** The JWKS URL is **`https://<host>/.well-known/jwks.json`**, where `<host>` is derived from **`domain`** (scheme and trailing slash stripped). Example: `domain: https://tenant.us.auth0.com` → fetch **`https://tenant.us.auth0.com/.well-known/jwks.json`**.
- **Caching / refresh:** `internal/custom/auth/authzero` uses **`github.com/MicahParks/keyfunc/v3`** `NewDefault`, which stores the JWK set and runs a **background refresh** for the remote JWKS URL (you do not configure polling in YAML).
- **Upstream generic auth** discovers **`jwks_uri`** via **`{authorizationServer}/.well-known/openid-configuration`** instead of a fixed `jwks.json` path (see `internal/auth/generic/generic.go`).

---

## MySQL SQL guardrails

Validation runs in **`internal/sources/mysql/mysql.go`** inside **`RunSQL`**:

- Rejects **`USE`** (word-boundary).
- Strips **`/* block */`** comments before checks.
- Rejects `` `other_db`.`table` `` when `other_db` ≠ configured source **`database`** (case-insensitive), with allowances for **`information_schema`**, **`performance_schema`**, **`mysql`**, **`sys`**.

Heuristic only—not a full SQL parser.

### Cloud SQL for MySQL (`type: cloud-sql-mysql`)

Upstream registers the Cloud SQL Go connector driver. **This fork** adds **`queryTimeout`** and **`queryParams`** on the source config, **parity with the plain `mysql` source**: values are appended to the DSN query string (`readTimeout`, default `parseTime=true`, plus any extra driver params). See **`internal/sources/cloudsqlmysql/cloud_sql_mysql.go`** (helpers `cloudSQLMySQLDSNQuery` / `cloudSQLMySQLDSNPathPrefix`). Without this, strict YAML rejects unknown keys such as `queryTimeout`.

---

## Re-syncing with upstream (`main`)

Use this section as the **checklist** each time you pull upstream into your fork.

**Releases (v1.1.0+):** Stable tags are published on **[googleapis/mcp-toolbox releases](https://github.com/googleapis/mcp-toolbox/releases)**. For a given tag (e.g. `v1.1.0`), the commit often matches **`genai-toolbox`** as well—verify with `git rev-parse v1.1.0` after `git fetch <remote> --tags`. Upstream **v1.1.0** uses the Go module path **`github.com/googleapis/mcp-toolbox/...`** (not `genai-toolbox`).

### 1. One-time: `upstream` remote

```bash
git remote add upstream https://github.com/googleapis/genai-toolbox.git
# Equivalent for tags: https://github.com/googleapis/mcp-toolbox.git
# or: git remote set-url upstream <url>
git fetch upstream --tags
```

### 2. Branch and merge (or rebase)

```bash
git checkout main   # or your default branch
git pull origin main
git checkout -b sync/upstream-$(date +%Y-%m-%d)   # Git Bash / macOS / Linux; PowerShell: use e.g. sync/upstream-2026-03-29
git merge upstream/main
# Or merge a release tag:  git merge v1.1.0
# Alternative: git rebase upstream/main  (cleaner history; rewrites your branch—coordinate with your team)
```

Resolve conflicts before continuing. **Prefer keeping fork behavior** for `custom:` middleware, billing/quota hooks, and `authzero`—see priority order below.

### 3. Where conflicts usually appear (resolve in this order)

| Priority | Area | Why |
|----------|------|-----|
| 1 | `internal/custom/**` | Your fork logic—keep your versions unless upstream fixes a bug you need. |
| 2 | `internal/sources/mysql/mysql.go` | Fork adds `customutil.ValidateSQLForDatabase` in `RunSQL`—re-apply that hunk if upstream edits `RunSQL`. |
| 2b | `internal/sources/cloudsqlmysql/cloud_sql_mysql.go` | Fork adds **`queryTimeout`** / **`queryParams`** DSN parity with `mysql`; re-apply if upstream edits Cloud SQL DSN building. |
| 3 | `internal/server/server.go` | Billing/quota context middleware, `debugLogAuthToken`, startup logs. |
| 4 | `internal/server/mcp.go` | MCP routing, PRM, Claude proxy registration. |
| 5 | `internal/server/mcp/v*/method.go` (all versions) | `EnrichContextWithAuthForBillingQuota`, `QuotaPreflightBeforeInvoke`, `LogAndPostBilling`. |
| 6 | `internal/server/api.go` | REST `/api` parity with MCP for billing/quota. |
| 7 | `internal/util/billing.go`, `internal/util/quota.go`, `billing_tokens_block.go` | Shared HTTP helpers. |
| 8 | `cmd/root.go` | Flags / `ToolboxUrl` / MCP auth validation. |

If upstream adds a **new MCP protocol version** directory under `internal/server/mcp/`, copy the same **three** call patterns from an existing `method.go` into the new handler.

### 4. Build and automated tests

```bash
go build ./...
go test ./internal/custom/... ./internal/sources/mysql/... ./internal/sources/cloudsqlmysql/... ./internal/util/... ./internal/server/... -count=1 -short
```

Add broader `./...` when you have time; fix any new upstream tests that assume stock behavior.

### 5. Manual smoke tests (non-production)

- Start with a config that sets **`quotaEndpoint`** and **`billingEndpoint`** (mock or dev URLs).
- Call **`tools/call`** (or REST **`/api`** if enabled) **with** a valid **`Authorization`** header.
- Confirm: quota preflight runs before invoke; billing POST runs after success; logs show expected `quota:` / `billing:` debug lines if log level allows.

### 6. Update this document after the sync

If upstream changed behavior you integrated, or you added keys / moved hooks:

- Update **`FORK.md`** tables (`custom:` keys, file paths).
- Note the **upstream tag or commit** you merged (e.g. in your PR description: `Merged upstream v1.1.0` / `mcp-toolbox`).

That way the **next** person (or future you) knows what “synced” means and what was verified.

### 7. Optional: patch file or scripted replay

If the same conflicts repeat every release, maintain a **`patches/`** directory with `.patch` files or a short script that re-applies known hunks **after** merge—only after reviewing upstream diffs, so you do not blind-apply stale patches.

---

## Fork file inventory (sync reference)

Use this table when merging **upstream**: re-apply or preserve these paths if Git conflicts.

### `internal/custom/**` (prefer keeping fork versions)

| File | Role |
|------|------|
| `internal/custom/README.md` | Pointers to this doc; merge-conflict tips. |
| `internal/custom/util/sql_validation.go` | `ValidateSQLForDatabase` (MySQL guardrails). |
| `internal/custom/util/sql_validation_test.go` | Tests for SQL validation. |
| `internal/custom/util/preflight.go` | `PerformPreflightCheck`: quota HTTP + billing “insufficient tokens” block gate. |
| `internal/custom/util/billing_context.go` | `EnrichContextWithAuthForBillingQuota`, `QuotaPreflightBeforeInvoke`. |
| `internal/custom/auth/authzero/authzero.go` | Auth0 JWT service: JWKS, `GetClaimsFromHeader`, config. |
| `internal/custom/auth/authzero/mcp_auth.go` | `ValidateMCPAuth` for MCP middleware. |
| `internal/custom/auth/authzero/*_test.go` | Unit tests. |
| `internal/custom/auth/hta/hta.go` | HTA auth kind (if enabled in config). |

### Billing, quota, and tool billing helpers

| File | Role |
|------|------|
| `internal/util/billing.go` | `BillingInfo`, `LogAndPostBilling`, context keys (`WithBillingEndpoint`, `WithJWTClaims`, …), sync variant. |
| `internal/util/billing_tokens_block.go` | In-process block after billing “insufficient tokens”; cleared on billing 2xx. |
| `internal/util/billing_tokens_block_test.go` | Tests for block / response heuristics. |
| `internal/util/quota.go` | Quota HTTP client, `CheckQuotaAndAuthorize`, context helpers. |
| `internal/tools/billing.go` | `BillingQueryFromToolInvocation`, `BillingRowCountFromResult` (billing payload fields). |
| `internal/tools/billing_test.go` | Tests for billing helpers. |

### Server integration (high conflict with upstream)

| File | Role |
|------|------|
| `internal/server/server.go` | `custom:` wiring, CORS, **billing/quota context** on requests, **`mcpAuthMiddleware`**, PRM + manual PRM + **fork PRM** routes, Claude proxy mount. |
| `internal/server/mcp.go` | MCP router, **`prmHandler`** (auth-based PRM JSON), SSE/HTTP handlers importing **`authzero`**. |
| `internal/server/mcp/v20241105/method.go` | Per-version: **`EnrichContextWithAuthForBillingQuota`**, **`QuotaPreflightBeforeInvoke`**, **`LogAndPostBilling`**. |
| `internal/server/mcp/v20250326/method.go` | Same pattern. |
| `internal/server/mcp/v20250618/method.go` | Same pattern. |
| `internal/server/mcp/v20251125/method.go` | Same pattern. |
| `internal/server/api.go` | REST `/api` parity for billing/quota hooks. |
| `internal/server/config.go` | Imports **`authzero`** / **`hta`** for YAML unmarshaling. |
| `internal/server/oauth_metadata.go` | Fork PRM parsing from `custom:` (`parseOAuthProtectedResourceMetadata`). |
| `internal/server/oauth_claude_proxy.go` | Claude OAuth proxy to Auth0. |
| `internal/server/prm.go` | `ProtectedResourceMetadata` struct (RFC 9728 fields). |

### MySQL sources

| File | Role |
|------|------|
| `internal/sources/mysql/mysql.go` | **`RunSQL`**: calls **`customutil.ValidateSQLForDatabase`** before `QueryContext`. Supports **`queryTimeout`** / **`queryParams`** (upstream). |
| `internal/sources/cloudsqlmysql/cloud_sql_mysql.go` | Cloud SQL connector pool; **fork**: **`queryTimeout`** / **`queryParams`** on DSN (same semantics as `mysql`). `dsn_test.go` covers query string. |

### CLI / config

| File | Role |
|------|------|
| `cmd/root.go` | Auth service registration import **`authzero`**; toolbox URL / validation. |
| `cmd/internal/config.go` | **`Custom`** map on config; **single** `mcpEnabled` auth service check. |

### Container / CI

| File | Role |
|------|------|
| `Dockerfile` | Multi-stage build; **`ARG BUILDPLATFORM`** / **`TARGETOS`** / **`TARGETARCH`** defaults so **plain `docker build`** (e.g. Cloud Build) does not get empty `--platform=$BUILDPLATFORM`. |
| `cloudbuild.yaml` | Your image build + deploy (project-specific). |

---

## References in tree (quick)

- `internal/util/billing.go`, `internal/util/quota.go` — HTTP clients and context keys.
- `internal/custom/util/preflight.go` — quota preflight orchestration.
- `internal/server/oauth_metadata.go`, `oauth_claude_proxy.go` — OAuth PRM and Claude proxy.
- `internal/tools/billing.go` — **`query` / `row_count`** for billing POST body.
