# Fork-specific code (`internal/custom`)

Implementation packages for this fork (Auth0 MCP, HTA helpers, SQL validation helpers, preflight wiring, etc.). **User-facing documentation** for `custom:` YAML keys, quota/billing behavior, and OAuth options lives in the repo root: **[FORK.md](../../FORK.md)**.

## Reducing merge conflicts with upstream genai-toolbox

1. **Keep most fork logic here** (`internal/custom/**`) so it rarely overlaps upstream file paths.
2. **Single choke points** where possible: MySQL SQL validation runs in `internal/sources/mysql/mysql.go` → `RunSQL` (one import + a few lines), not in every tool under `internal/tools/mysql/`.
3. **Server / MCP** changes are harder to isolate; prefer small callouts to `internal/custom/util` helpers over duplicating large blocks in upstream-shaped files.
4. On each upstream sync: follow **[FORK.md — Re-syncing with upstream](../../FORK.md#re-syncing-with-upstream-main)** (git steps, conflict priority table, `go test` commands, smoke tests, and when to update `FORK.md`).
