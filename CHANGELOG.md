# Changelog

All notable changes to Agentopsy are documented here.

## [0.3.0] - Unreleased

### Added

- Provider adapters for the incremental collector while preserving forensic parsers.
- Versioned local SQLite state with file identity, offsets, partial-line recovery, sessions, health events and bounded occurrence counters.
- `agentopsyd` / `agentopsy service` passive incremental service commands.
- `agentopsy health`, `service-status`, `trends`, and handoff validation commands.
- Deterministic health bands, hysteresis, cooldown-aware notifications, optional desktop notification, and passive Herdr adapter foundation.
- User-level systemd service example.

### Safety

- No provider transcript writes, network upload, AI calls, telemetry, or automatic session rotation.

## [0.2.0] - 2026-08-19

### Added

- Public project name: **Agentopsy**.
- `--sessions` minimal ID/date listing.
- `--session ID` exact or unique-prefix selection, repeatable.
- `--last [N]` latest N sessions per selected provider.
- `--summary` compact provider-only report mode.
- `--export FILE` combined Markdown export.
- `--export-claude FILE` provider-specific Markdown export.
- `--export-codex FILE` provider-specific Markdown export.
- Composable selection/export semantics.
- Release-grade README, design, security, contribution and roadmap docs.
- Packaging metadata for a `agentopsy` console command.

### Changed

- `--markdown FILE` remains as a compatibility alias for `--export FILE`.
- Passive `--watch` mode is now explicitly labelled a legacy polling prototype.
- Default state/report path renamed to `~/.local/state/agentopsy`.
- Public examples use synthetic/generic IDs and project names only.

### Security / privacy

- Removed real session reports and private analysis artefacts from the public package.
- Scrubbed user/machine/project-specific examples from release source and documentation.

## [0.1.0] - 2026-08-18

Initial private prototype:

- Claude Code + Codex transcript parsing;
- automatic store discovery;
- activity bursts;
- tool/context/token analysis;
- workflow defect flags;
- Markdown and JSON reports;
- polling prototype.
