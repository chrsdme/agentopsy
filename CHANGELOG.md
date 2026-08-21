# Changelog

All notable changes to Agentopsy are documented here.

## [0.4.2] - 2026-08-21

### Fixed

- Calibration profiles now record provider capability per metric. Claude's
  context percentage is explicitly unavailable because its occupancy is an
  absolute-token proxy, so it is skipped during adoption rather than treated
  as insufficient evidence; applicable low-confidence metrics still block.
- Package metadata now matches the runtime version.

## [0.4.1] - 2026-08-21

### Fixed

- SQLite schema v5 separates a provider's native conversation ID from its
  execution-stream/rollout ID. Streams have explicit `MAIN`, `SUBAGENT`, or
  `GUARDIAN` roles and parent links, so Codex auto-review streams cannot merge
  with their parent rollout.
- A v4-to-v5 upgrade invalidates unsplittable derived aggregates/cursors and
  replays discoverable provider transcripts under a durable fail-closed marker;
  v4 calibration profiles are discarded rather than adopted under v5 semantics.
- Live health uses latest current telemetry; historical peak remains a
  separate forensic value. Missing context percentages are N/A or explicitly
  labelled proxies, never silently SAFE.
- Default trend, calibration, and insight populations are workflow MAIN
  streams with activity; auxiliary and incomplete rows remain inspectable.
- Installer input validation is performed before files are modified, and
  install/remove records ownership of the Codex hooks feature flag.

## [0.4.0] - 2026-08-20

### Changed

- Context Guardian is complete: live session-health scoring, one-to-five
  marker/lane/overall efficiency scores, causal-risk analysis, calibration
  with confidence, deterministic historical insights, policy management, and
  deterministic replay are now available from the local CLI/service.
- The incremental service now exposes `--auto-act observe|compact|full`
  (default `observe`) and routes high-context candidates through the
  fail-closed control decision path.
- Active control remains unavailable unless an exact native session and
  harness mapping, safe boundary, capability, and independently observable
  result are all established.
- Compaction THRASH classification now requires observed frequent timing plus
  rapid refill, ineffective reduction, or repeated post-compaction work;
  effective spaced compactions are not THRASH by count alone.
- Persisted notification cooldown, enablement, and minimum severity now affect
  the real incremental service path.
- The live collector no longer advertises an unreachable compound-context
  emergency when required independent signals are not measured.
- Codex compact control can now execute end to end: a Codex lifecycle hook
  (`agentopsy integration install codex`) registers an exact native
  session/pane identity with Herdr, `--auto-act compact` requests a
  Herdr-delivered `/compact`, and the result is only marked `COMPACT_VERIFIED`
  after independent post-request Codex provider lifecycle evidence and a
  measured context-token reduction are observed for that same session. A
  Herdr transport timeout alone is never treated as success. Claude native
  control remains unavailable.

## [0.3.0] - 2026-08-19

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
