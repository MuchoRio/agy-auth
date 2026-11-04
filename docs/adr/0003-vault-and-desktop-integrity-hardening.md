# ADR-0003: Vault key-orphaning guard, Desktop encryption at rest, and safe process discovery

- **Status:** Accepted
- **Date:** 2026-11-04
- **Decision makers:** MuchoRio
- **Consulted:**
- **Related:** [`docs/adr/0002-antigravity-desktop-support.md`](0002-antigravity-desktop-support.md), [`docs/exec-plans/completed/2026-11-04_security-and-integrity-hardening.md`](../exec-plans/completed/2026-11-04_security-and-integrity-hardening.md), [`docs/internals.md`](../internals.md)

## Context

A comprehensive security and data-integrity audit of `agy-auth` `v0.3.0` uncovered several failure modes across `internal/agy`, `internal/desktop`, `internal/registry`, and `internal/cli`:

1. **Vault key orphaning:** When `encryption.key` was missing from both the OS keyring and disk, `SnapshotVault.loadKey(true)` generated a new random 256-bit key unconditionally—even if encrypted `accounts/*.json` or `backups/active-*.json` already existed on disk—permanently orphaning all existing snapshots.
2. **Unsafe `pgrep -f` process termination:** `internal/desktop` fell back to `pgrep -f antigravity` on macOS/BSD systems where `/proc` is absent, matching any shell, editor, or AI agent whose command-line arguments contained `antigravity` and sending `SIGKILL` after 5 seconds during `--relaunch` or `--close-desktop`.
3. **Plaintext Desktop snapshots, missing SQLite WAL files, and non-atomic swaps:** Desktop snapshots (`Cookies`, `Local Storage`, `app_storage.json`, `Preferences`) were stored in plaintext, omitted `Cookies-wal` and `Cookies-shm`, did not clean stale `-wal`/`-shm` companion files on restore, deleted live directories before copying replacements, and were not pruned by `agy-auth clean`.
4. **Live Desktop capture and cross-account contamination:** `agy-auth add` captured Desktop files while Antigravity Desktop was running or when Desktop's `app_storage.json` belonged to a different account than the CLI credential, and `switch`/`rotate` did not sync the outgoing account's live Desktop profile before overwriting it.

## Decision drivers

- Never silently orphan existing encrypted snapshots when `encryption.key` is missing or unreadable.
- Never terminate unrelated user processes whose command-line arguments happen to contain the string `antigravity`.
- Encrypt all stored Desktop session files and backups at rest with AES-256-GCM while maintaining backward compatibility with existing plaintext snapshots.
- Guarantee atomic directory swaps with automatic rollback and prevent SQLite WAL / LevelDB corruption or cross-account profile contamination.

## Considered options

- **Option A: Keep Desktop snapshots plaintext and rely on OS directory permissions (`0700`)** — Rejected because CLI snapshots already use `SnapshotVault` AES-256-GCM encryption at rest; leaving Desktop SQLite cookies and LevelDB storage unencrypted creates an inconsistent security boundary.
- **Option B: Route Desktop snapshots/backups through `backup.Codec` (`SnapshotVault`), add executable-only process inspection, and enforce vault/capture guards** — Encrypt all Desktop files via `SnapshotVault`, include `Cookies-wal`/`Cookies-shm`, use `os.MkdirTemp` staging + `swapDirAtomic` rollback, inspect exact executables via `ps -axo pid=,args=` (macOS/BSD) and `tasklist` (Windows), and block key regeneration when ciphertext exists.

## Decision

Adopt **Option B**:
1. `SnapshotVault.loadKey(true)` inspects `accounts/` and `backups/` via `hasExistingEncryptedData` before creating a new key and returns `ErrSnapshotKey` if encrypted files already exist; `encryption.key.lock` and `.registry.lock` automatically recover stale locks older than 10 seconds.
2. `internal/desktop` encrypts all snapshot and backup files through `backup.Codec` (`SnapshotVault`), includes `Cookies-wal` and `Cookies-shm`, removes stale companion files on restore, and swaps directories atomically with `.old-*` rollback.
3. Process discovery on macOS/BSD uses `ps -axo pid=,args=` (`parsePSOutput` / `matchDesktopProcessLine`) and on Windows uses `tasklist` / `taskkill`, matching only the executable token and excluding `os.Getpid()` and Electron `--type=` helpers.
4. `cmdAdd` skips Desktop capture with a warning if Antigravity Desktop is running or if `DetectAccountEmail()` (`app_storage.json`) conflicts with the CLI account email; `switchAccount` syncs the outgoing account's live Desktop profile before restoring the target account.
5. `backup.PruneAll` includes `PruneDesktop`, and `internal/harness/lint` enforces `output-boundary`, `atomic-writes`, and `file-permissions` across `internal/desktop`, `internal/backup`, `internal/usage`, and `internal/cli`.

## Consequences

- **Good:** Zero silent key-orphaning risk; Desktop cookies and LevelDB tokens are encrypted at rest; `--relaunch` and `--close-desktop` can never kill unrelated user shells or agents; atomic directory swaps prevent half-restored Desktop profiles.
- **Neutral:** `SnapshotVault.Decode` transparently passes through unencrypted bytes without the `agy-auth-encrypted:v1:` header, preserving backward compatibility with legacy plaintext Desktop snapshots.
- **Bad:** None.

## Confirmation

- Verified in CI (`harness verify --profile ci`, GitHub Actions run `#41795230069`) and shipped in `v0.3.1`.
