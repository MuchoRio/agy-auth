# Antigravity IDE/Hub support, model override diagnostics, and full audit remediation

| Field | Value |
|---|---|
| Status | completed |
| Owner | MuchoRio |
| Date | 2026-11-05 |
| Related | [`docs/adr/0003-vault-and-desktop-integrity-hardening.md`](../../adr/0003-vault-and-desktop-integrity-hardening.md), [`docs/adr/0004-antigravity-ide-hub-and-user-scope-sync.md`](../../adr/0004-antigravity-ide-hub-and-user-scope-sync.md), [`docs/internals.md`](../../internals.md) |

## Objective

Fix Antigravity 2.0 / IDE (`Antigravity IDE.app`) profile discovery, `credential-user-scope` synchronization, `agy --hub` daemon lifecycle handling, and CLI `settings.json` model-override detection, while remediating all confirmed findings from the 4-stage repository audit (`v0.3.2`).

## Context

Forensic inspection on macOS (`Megastars-MacBook-Pro-6`) revealed why selecting `Gemini 4 Argon` in Terminal (`agy`) or `Antigravity IDE` still executed `Gemini 3.8 Flash` and why Desktop switching missed active IDE sessions:
1. `~/.gemini/antigravity-cli/settings.json` contained a persistent `"model": "Gemini 3.8 Flash (High)"` override that `agy` applied on every startup/resume without `agy-auth` reporting it.
2. `internal/desktop` resolved macOS config to `~/Library/Application Support/Antigravity`, which on case-insensitive APFS collides with `~/Library/Application Support/antigravity` (containing only `credential-user-scope`), whereas the Electron IDE profile lives in `~/Library/Application Support/Antigravity IDE` and the app bundle is `/Applications/Antigravity IDE.app/Contents/MacOS/Electron`.
3. `agy-auth` did not update `credential-user-scope` (`"u" + sha256(sub)[:16]`) or detect/restart the background `agy --hub` daemon that caches account auth and model entitlements for the IDE.
4. Additional audit findings identified silent Keychain write failures in `Storage.Write`, uncached 198 MB binary reads in `oauth.DiscoverClient()`, non-persisted token refreshes in `usage.Client`, missing `desktop/` checks in `SnapshotVault.hasExistingEncryptedData`, duplicate `writeFileAtomic` helpers, and upstream release URL clobbering in `update.go`.

## Scope

### In scope

- `internal/backup`: export canonical `WriteFileAtomic` and use it across `agy`, `registry`, and `cli`.
- `internal/agy`: surface `keyringErr` in `Storage.Write` when an existing keyring entry would shadow the file fallback; inspect `desktop/` and `backups/desktop/` in `hasExistingEncryptedData`; export `CopyBytes`.
- `internal/registry`: ensure `HasDesktopProfile` checks for non-empty profile directories; add `Store.Update` holding `.registry.lock` across `Load -> Modify -> Save`.
- `internal/oauth` & `internal/usage`: cache `DiscoverClient()` by `(path, mtime, size)` with streaming chunk scan; update and persist refreshed access tokens via `OnTokenRefresh`.
- `internal/desktop`: support `Antigravity IDE` config/binary/process paths; add `UserScopeForSubject`, `WriteUserScope`, `ReadUserScope`, and `DetectAccountSubjectScope`.
- `internal/cli`: cross-platform `runningAgyCount()` and `agy --hub` daemon termination on `--relaunch`/`--close-desktop`; detect `"model"` overrides in `~/.gemini/antigravity-cli/settings.json`; move quota policy helpers to `usage.go`; improve `liveSwitch` error reporting; point `defaultUpdateReleaseURL` to `MuchoRio/agy-auth`.
- `internal/harness/lint`: include `internal/cli` in `file-permissions` check.

### Out of scope

- Modifying closed-source `agy` or `Antigravity IDE.app` binaries.

## Expected paths

- `internal/backup/backup.go`
- `internal/agy/{snapshot,storage,token}.go`
- `internal/registry/registry.go`
- `internal/oauth/oauth.go`
- `internal/usage/usage.go`
- `internal/desktop/desktop.go`
- `internal/cli/{app,cmd_alias,cmd_config,cmd_import,cmd_list,cmd_login,cmd_remove,cmd_rotate,cmd_status,cmd_switch,live,update,usage,util}.go`
- `internal/harness/lint/lint.go`
- `docs/...`, `CHANGELOG.md`, `package.json`

## Risks

- **Case-insensitive macOS APFS collision between `Antigravity` and `antigravity`:**
  *Mitigation:* Check whether candidate directory actually contains desktop session files (`HasProfile`) or `Antigravity IDE` before falling back, so lowercase `antigravity` (which only holds `credential-user-scope`) is never treated as the Electron profile root.
- **Test isolation for `credential-user-scope` and `settings.json`:**
  *Mitigation:* Only write `credential-user-scope` to the default OS path when `UserScopeFile` is explicitly configured or when using the default desktop config directory outside tests.

## Acceptance criteria

- [x] `DefaultConfigDir()`, `DefaultBinaryPath()`, and `matchDesktopProcessLine()` support `Antigravity IDE`.
- [x] `UserScopeForSubject` produces `"u" + sha256(sub)[:16]` and updates `credential-user-scope` on account activation.
- [x] `runningAgyCount()` works across Linux, macOS, and Windows, and `--relaunch`/`--close-desktop` stops `agy --hub` processes.
- [x] `status` and `switch` surface hardcoded CLI `"model"` overrides from `~/.gemini/antigravity-cli/settings.json`.
- [x] `DiscoverClient()` caches results and scans in 4 MB chunks; refreshed usage tokens are persisted via callback.
- [x] `Storage.Write`, `hasExistingEncryptedData`, `Store.Update`, and `backup.WriteFileAtomic` pass all unit and harness checks.
- [x] `harness verify --profile ci` passes in GitHub Actions and `v0.3.2` is released.

## Verification plan

```shell
make verify
make verify-full
make verify-ci
```
