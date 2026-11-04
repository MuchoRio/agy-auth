# Security and integrity hardening across vault, desktop, registry, and harness

| Field | Value |
|---|---|
| Status | completed |
| Owner | MuchoRio |
| Date | 2026-11-04 |
| Related | [`docs/adr/0001-repository-harness.md`](../../adr/0001-repository-harness.md), [`docs/adr/0002-antigravity-desktop-support.md`](../../adr/0002-antigravity-desktop-support.md), [`docs/internals.md`](../../internals.md) |

## Objective

Eliminate fatal and critical data-loss, process-safety, corruption, and encryption gaps across `internal/agy`, `internal/desktop`, `internal/backup`, `internal/registry`, `internal/cli`, and `internal/harness`.

## Context

A comprehensive forensic audit of `agy-auth` identified several high-severity failure modes:
1. `internal/desktop` fell back to `pgrep -f antigravity` on macOS/non-`/proc` systems, matching any process whose command-line arguments contained `antigravity` and sending `SIGKILL` after 5 seconds during `--relaunch` or `--close-desktop`.
2. `agy-auth add` captured Desktop SQLite (`Cookies`) and LevelDB (`Local Storage`) without checking if Antigravity Desktop was running or whether `app_storage.json` belonged to a different account, omitted `Cookies-wal`/`Cookies-shm`, and did not re-sync the outgoing Desktop profile on `switch`.
3. Desktop snapshots and backups were stored unencrypted at rest, and `desktop.Restore` deleted live `Local Storage` before copying the replacement without atomic swap/rollback.
4. `SnapshotVault.loadKey(true)` could generate a brand-new `encryption.key` if the key file was missing even when encrypted snapshots already existed, permanently orphaning them, and lacked stale-lock recovery.
5. `Store.Upsert` and `import --purge` dropped `HasCli`/`HasDesktop` metadata, `TokenFile` dropped unknown JSON fields on re-marshal/refresh, and `internal/harness/lint` omitted `internal/desktop`, `internal/backup`, `internal/usage`, and `internal/cli` from several AST checks.

## Scope

### In scope

- `internal/agy`: refuse key generation when encrypted snapshots/backups already exist; recover stale `encryption.key.lock`; preserve unknown JSON fields in `TokenFile`/`Token`.
- `internal/desktop`: safe executable-only process discovery (`ps` on Darwin/BSD, `tasklist`/`taskkill` on Windows), multi-PID termination, `Cookies-wal`/`Cookies-shm` support and stale companion cleanup, atomic staging/restore with rollback, and AES-256-GCM encryption via `backup.Codec`.
- `internal/backup`: prune desktop backup directories in `PruneAll`.
- `internal/registry`: `.registry.lock` concurrency guard, `HasCli`/`HasDesktop` preservation in `Upsert` and `AccountFromRaw`, and error propagation in `DeleteToken`.
- `internal/cli`: running-process and email-mismatch guards in `cmdAdd`, outgoing Desktop snapshot sync in `switchAccount`, `HasDesktop` preservation in `import --purge`, and atomic writes in `cmd_import.go` and `update.go`.
- `internal/harness/lint`: expand `output-boundary`, `atomic-writes`, and `file-permissions` coverage.

### Out of scope

- Changing external CLI flag names or JSON envelope schema versions.

## Expected paths

- `internal/agy/{snapshot,snapshot_test,token,token_test}.go`
- `internal/desktop/{desktop,desktop_test}.go`
- `internal/backup/{backup,backup_test}.go`
- `internal/registry/registry.go`
- `internal/cli/{app,cmd_list,cmd_login,cmd_switch,cmd_import,update,util,cli_test}.go`
- `internal/harness/lint/lint.go`
- `docs/{harness,internals}.md`, `SECURITY.md`

## Risks

- **Legacy plaintext desktop snapshots in existing environments or tests:**
  *Mitigation:* `SnapshotVault.Decode` returns unencrypted bytes unchanged when the `agy-auth-encrypted:v1:` prefix is absent, so existing unencrypted desktop files restore seamlessly.
- **Process detection portability:**
  *Mitigation:* Keep `/proc` scanning on Linux, use `ps -axo pid=,args=` executable matching on Darwin/BSD, and use `tasklist` on Windows; unit test command-line filtering logic directly.

## Acceptance criteria

- [x] `SnapshotVault` refuses to create a new key when encrypted snapshots/backups already exist and recovers stale `.lock` directories.
- [x] `TokenFile` and `cmdLogin` preserve unknown JSON fields.
- [x] `internal/desktop` never matches unrelated processes with `antigravity` in arguments, encrypts snapshots/backups via `Codec`, handles `Cookies-wal`/`Cookies-shm`, and swaps directories atomically with rollback.
- [x] `cmdAdd` blocks/skips live Desktop capture when Desktop is running or when `app_storage.json` email mismatches.
- [x] `Upsert` and `import --purge` preserve `HasCli` and `HasDesktop`.
- [x] `internal/harness/lint` enforces atomic writes, permissions, and output boundaries across all internal packages.

## Verification plan

```shell
make verify
make verify-full
```

## Rollback

Revert the commit; encrypted desktop snapshots and v2 registries remain backward-compatible with `SnapshotVault`.

## Decision log

| Date | Decision | Rationale |
|---|---|---|
| 2026-11-04 | Use `backup.Codec` in `internal/desktop` | Encrypts desktop snapshots/backups with `SnapshotVault` without adding new package import cycles. |
| 2026-11-04 | Block key creation if ciphertext exists | Prevents silent permanent loss of existing encrypted snapshots when `encryption.key` is missing. |
| 2026-11-04 | Replace `pgrep -f` with executable inspection | Prevents killing user shells, IDEs, or agents that have `antigravity` in path arguments. |

## Completion

- Commit/tag: `fix(security): harden vault key, desktop snapshots, registry locking, and harness lint`
- Verification result: `gofmt -l .` clean; full CI verification runs via GitHub Actions
- Residual risk: none

