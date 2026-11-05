# ADR-0004: Antigravity IDE Support, Hub Termination, and User Scope Synchronization

- **Status:** Accepted
- **Date:** 2026-11-05
- **Decision makers:** Rio, Kaela Kovalskia
- **Related:** [ADR-0002](0002-antigravity-desktop-support.md), [ADR-0003](0003-vault-and-desktop-integrity-hardening.md), [Execution Plan](../../docs/exec-plans/completed/2026-11-05_antigravity-ide-hub-and-audit-remediation.md)

## Context

Google Antigravity evolved into Antigravity 2.0 / Antigravity IDE (`Antigravity IDE.app` on macOS). The IDE pairs an Electron front-end with an active background `agy --hub` daemon and maintains account entitlement state across two surfaces:
1. The OAuth credential stored in the OS Keychain/file mirror.
2. A user scope identifier file at `~/.gemini/antigravity-cli/credential-user-scope` (or `~/Library/Application Support/antigravity/credential-user-scope`) formatted as `"u" + sha256(sub)[:16]`.

When users switched accounts via `agy-auth switch`, only the raw OAuth credential was swapped. As a result:
- The persistent `agy --hub` daemon continued serving the previous account's context.
- The `credential-user-scope` remained anchored to the old user subject, causing the IDE to restrict model entitlements (e.g. falling back from Gemini 4 Argon to Gemini 3.8 Flash).
- A hardcoded `"model"` key in `~/.gemini/antigravity-cli/settings.json` could silently override model selection across sessions.

## Decision drivers

- Zero-hallucination model entitlement parity between CLI and IDE.
- Safe process lifecycle management for both the GUI app and its background `--hub` daemon.
- Complete data integrity preventing cross-account profile capture.

## Considered options

- **Option A: CLI-only switching** — Leave IDE state and `--hub` daemon untouched. Users must manually restart the IDE and reset user scope.
- **Option B: Full IDE + Hub + User Scope synchronization (Chosen)** — Dynamically detect `Antigravity IDE`, write the deterministic `credential-user-scope` on switch/add/login, terminate background `agy --hub` daemons on switch relaunch, and warn on `settings.json` `"model"` overrides.

## Decision

We chose **Option B**.
1. **Config & Executable Detection:** `DefaultConfigDir()` and `DefaultBinaryPath()` recognize `Antigravity IDE` alongside legacy `Antigravity`.
2. **User Scope Sync:** Calculate `"u" + sha256(sub)[:16]` and write `credential-user-scope` atomically on switch, login, add, and activate.
3. **Hub Daemon Termination:** `TerminateHub` safely terminates `agy --hub` daemons during switch with `--relaunch` or `--close-desktop`.
4. **Desktop Capture Guard:** Verify `credential-user-scope` against account subject before capturing desktop profiles.
5. **Model Pinning Telemetry:** Inspect `settings.json` and warn users if a pinned model overrides interactive choices.

## Consequences

- **Good:** Account switching seamlessly updates both CLI and IDE model entitlements; prevents subtle model fallbacks and stale daemon state.
- **Neutral:** Switching with `--relaunch` terminates the background `--hub` daemon, causing the IDE to reconnect or restart its hub on next command.
- **Bad:** None identified.

## Confirmation

Verified via unit tests in `internal/desktop/desktop_test.go` (`TestUserScopeAndSubjectMatch`, `TestMatchAntigravityIDEAndAgyHubProcessLines`) and `internal/cli/cli_test.go` (`TestSwitchUpdatesUserScopeAndWarnsOnCLIModelOverride`).
