# Fork-specific code (`internal/custom`)

Implementation packages for this fork (Auth0 MCP, HTA helpers, SQL validation helpers, preflight wiring, etc.). **User-facing documentation** for `custom:` YAML keys, quota/billing behavior, OAuth options, and **ChatGPT domain verification** lives in the repo root: **[FORK.md](../../FORK.md)**.

## Reducing merge conflicts with upstream genai-toolbox

1. **Keep most fork logic here** (`internal/custom/**`) so it rarely overlaps upstream file paths.
2. **Single choke points** where possible: `ValidateSQLForDatabase` runs in `internal/sources/mysql/mysql.go` → `RunSQL`. **User-SQL / ChatGPT introspection denylist** (`ValidateExecuteSQL`) runs in `internal/tools/mysql/mysqlexecutesql` so it applies to **mysql and cloud-sql-mysql**, without breaking `list_tables` (which must query `INFORMATION_SCHEMA` via `RunSQL`).
3. **Server / MCP** changes are harder to isolate; prefer small callouts to `internal/custom/util` helpers over duplicating large blocks in upstream-shaped files.
4. On each upstream sync: follow **[FORK.md — Re-syncing with upstream](../../FORK.md#re-syncing-with-upstream-main)** (git steps, conflict priority table, `go test` commands, smoke tests, and when to update `FORK.md`).
