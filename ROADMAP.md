# Agentopsy Roadmap

Agentopsy keeps two useful layers: a standalone, deterministic forensic CLI
and an optional local incremental service. Both analyse provider transcripts
read-only and keep raw transcript bodies out of SQLite by default.

## Released foundations

### v0.2 — Public CLI foundation

Released 2026-08-19. Claude Code and Codex CLI discovery/parsing, file/directory
and ZIP inputs, session selection, Markdown/JSON exports, workflow defect
flags, and synthetic-only public tests are complete.

### v0.3 — Incremental collector

Released 2026-08-19. `agentopsyd` persists local file identity, offsets and
partial-line recovery so unchanged transcripts are not reparsed. It provides
health/trend queries, bounded SQLite state, notifications/cooldowns, handoff
validation, and a user-service example. The older `agentopsy --watch` full
rescan loop remains a compatibility mode only.

### v0.4 — Context Guardian

Released 2026-08-20. Context Guardian adds live session-health scoring,
one-to-five marker and overall efficiency scores, causal risk analysis,
context pressure/velocity/tool-output/repetition/amplification signals,
personal calibration and confidence, deterministic historical insights,
policy show/export/import/reset, and deterministic Guardian replay.

`observe` is the safe default. Codex automatic `/compact` is supported only
when exact transcript/native-session/Herdr-pane identity, current safe-idle
state, provider lifecycle evidence, and post-action context reduction all
match. Missing or ambiguous evidence fails closed. Claude automatic control,
automatic `/new`, `/clear`, reset, and rotation are unavailable. `full` mode
does not make unsupported rotation actions available.

### v0.5 — Claude runtime telemetry

Released 2026-08-22. The optional Claude status-line bridge adds exact
MAIN-session identity resolution and preserves the distinction between model
capacity, current input-context occupancy, and auto-compact operational window.
Qualification is evidence-gated and fail-closed.

### v0.5.1 — Claude 2.1.241 compatibility

Released 2026-08-23. Empirical compatibility qualification covers the
version-specific post-compact all-zero status-line behavior without treating it
as a universal zero-token rule.

### v0.6 — Semantic evidence journal

Released 2026-08-23. Privacy-safe aggregate semantic evidence, bounded
transition observations, and opaque structural field fingerprints are stored
under schema version 6.

### v0.6.1 — Release hardening

Released 2026-08-25. This release improves CI baseline/tag handling, Claude
`remaining_percentage` structural recognition, and StateStore failure-path
resource cleanup.

## Future directions

A local comparative optimizer remains a candidate, not a committed versioned
release. Evidence-driven work may compare a user's own policy/calibration
outcomes and surface reviewable workflow improvements while preserving privacy
and fail-closed control boundaries. It will not imply raw-transcript retention,
hosted telemetry, universal provider control, automatic Claude control, or
automatic rotation.

## Provider support

Additional parsers may be considered when a provider has inspectable local
records and can map cleanly to the normalized model without pretending that
unavailable telemetry is measured. Provider-specific assumptions remain
isolated and unavailable signals remain N/A/UNAVAILABLE.
