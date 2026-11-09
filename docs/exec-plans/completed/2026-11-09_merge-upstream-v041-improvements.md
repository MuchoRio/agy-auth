# Merge Upstream v0.4.1 Improvements into Enterprise Hardened agy-auth

| Field | Value |
|---|---|
| Status | completed |
| Owner | Kaela Kovalskia (Ela 🌸) & Rio |
| Date | 2026-11-09 |
| Target Version | `0.4.2` |
| Related | `internal/agy`, `internal/registry`, `internal/cli`, `internal/desktop`, `docs/adr` |

## Objective

Surgically merge and integrate all valid, verified upstream improvements from `fikrilal/agy-auth` (tags `v0.4.0` and `v0.4.1`) into the enterprise-hardened `MuchoRio/agy-auth` fork (`v0.3.2`), creating the unified `v0.4.2` release without regressing security hardening, Antigravity IDE hub termination, user-scope synchronization, or token-refresh telemetry callbacks.

## Upstream Analysis & Assessment

1. **Bugfix: Interactive Stdin Goroutine Leak (`9bb76f8`)**:
   - **Verdict**: Critical & 100% Valid. Prevents terminal hangs on subsequent stdin prompts (`Update now? [y/N]`) after exiting the interactive picker or live view via `waitForReadable` and `stop <-chan struct{}` cancellation.
2. **Feature: Per-Account CLI Installation ID (`58fcc2c`) & Desktop Updater ID (`d7a4af3`)**:
   - **Verdict**: High Value & 100% Valid. Preserves UUID continuity per account, preventing Google Antigravity from treating every account swap as a newly initialized machine.
3. **Feature: `list --all` flag & Quota Group Hint (`5e0d30e`)**:
   - **Verdict**: Ergonomic & 100% Valid. Allows users to view all quota groups directly from `agy-auth list --all`.
4. **UX Enhancements**:
   - Centralized terminal loading spinner (`cc8c8fc`).
   - Cyan table headers and horizontal table dividers (`7674fad`).
   - Bold yellow active account marker and human-readable relative reset timestamps (`5833598`).
   - Enhanced switch & rotate summary formatting (`c48e22e`).
   - **Verdict**: Polished & 100% Valid.

## Preservation of MuchoRio Enterprise Enhancements

The following custom features in `MuchoRio/agy-auth` MUST be preserved:
- Security hardening (ADR-0003): permission checks, encrypted vault validation, mutex concurrency guards.
- Antigravity IDE integration (ADR-0004): multi-OS configuration directories, `credential-user-scope` (`"u" + sha256(sub)[:16]`), `TerminateHub` daemon termination.
- Settings model override detector: warns when hardcoded `"model"` in `settings.json` hijacks UI dropdown choices.
- In-memory token refresh callback (`OnTokenRefresh`) during usage lookups.
- Discovery client 4MB chunked streaming with mutex guard.
- Release URL pointed to `MuchoRio/agy-auth`.

## Execution Steps

1. **Port Low-Level Utilities**:
   - `internal/agy/installation.go` + tests.
   - `internal/cli/poll_unix.go` and `internal/cli/poll_windows.go`.
   - `internal/cli/keys.go` with cancellation support.
   - `internal/cli/spinner.go` loading spinner.
   - `internal/cli/util.go` with `formatResetTime`.
2. **Port Registry & Desktop Lifecycle**:
   - Update `internal/registry/registry.go` with installation & updater ID persistence methods, protected by mutex.
   - Update `internal/desktop/desktop.go` with `UpdaterIDFile`, `UpdaterIDPath`, and `copyUpdaterID`.
   - `internal/cli/installation.go` and `internal/cli/desktop_updater.go`.
3. **Port CLI Commands & Table UI**:
   - `internal/cli/table.go` and `internal/cli/render.go`.
   - `internal/cli/cmd_list.go` with `--all` and tip.
   - `internal/cli/cmd_switch.go` with summary formatting + preserving IDE hub & user-scope sync.
   - `internal/cli/cmd_usage.go` with spinners and formatted reset times.
   - `internal/cli/cmd_import.go` and `internal/cli/cmd_login.go`.
   - `internal/cli/spec.go`.
4. **Documentation & ADRs**:
   - Renumber upstream ADRs to `docs/adr/0005-per-account-installation-id.md` and `docs/adr/0006-per-account-desktop-updater-id.md`.
   - Update `docs/adr/README.md` and `CHANGELOG.md`.
5. **Harness Verification & Gate**:
   - Run `make verify-full` and `go test ./...`.
6. **Release & Push**:
   - Bump version to `0.4.2`.
   - Git commit & annotated tag `v0.4.2`.
   - Push to `MuchoRio/agy-auth`.
   - Create GitHub release `v0.4.2` with prebuilt binaries.
   - Deploy local binaries.
