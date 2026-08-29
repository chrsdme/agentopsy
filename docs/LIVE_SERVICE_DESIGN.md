# Agentopsy Live Service Design

`agentopsyd` is the optional local, incremental companion to the forensic
CLI. It reads provider transcripts but never modifies them. `observe` is its
safe default; service control is opt-in and fails closed.

## Current architecture

```text
Claude/Codex JSONL ──> discovery + file cursor ──> incremental reducers
                              │                         │
                              └── changed tails only      ├── SQLite aggregates
                                                         ├── health/policy
                                                         └── local notification
```

The collector persists a provider, path, filesystem identity, size, mtime,
parsed offset, partial-line buffer, session ID, and parser version. On a
normal scan it avoids reparsing history: appended files are read from their
saved offset, and truncation/replacement rebuilds only the affected file.
The legacy `agentopsy --watch` loop remains available for compatibility but
rescans complete stores and is not the recommended service path.

## Local state and privacy

The default database is `~/.local/state/agentopsy/agentopsy.db`; use
`--state-dir` or `AGENTOPSY_STATE_DIR` to select another location. Migrations
are transactional and schema-versioned.

SQLite contains file cursors, sessions, health/Guardian events, compact
telemetry samples, notification state, bounded occurrence hashes, policy and
calibration data, and short-lived identity/lifecycle metadata. It does not
persist transcript bodies by default. Unavailable provider telemetry remains
N/A/UNAVAILABLE instead of being recorded as zero or as a health penalty.

## Session health

The service scores context pressure and velocity, tool-output pressure,
repetition, amplification, compaction health, and related causal combinations.
It exposes one-to-five markers, lane scores, an overall efficiency score,
severity, action safety, and explainable causal risk. Local calibration keeps
confidence and robust reference statistics reviewable; it cannot weaken
factory safety ceilings. Historical insights and `guardian replay` operate on
derived local state and are deterministic.

The factory context policy uses watch 50%, checkpoint 65%, rotation
recommendation 80%, and recovery below 45%, with persisted notification
cooldowns. These are conservative policy defaults, not universal model
limits. Codex occupancy uses provider-reported context-window data when
available; Claude’s live occupancy is an explicitly labelled proxy because it
lacks a universal denominator. Account or subscription quota is not a signal.

## Commands and service installation

```bash
# one incremental scan
agentopsyd once --auto-act observe

# foreground user service
agentopsyd run --foreground --interval 20 --auto-act observe

# inspect or configure derived local state
agentopsy health
agentopsy service-status
agentopsy trends --days 7
agentopsy calibrate status
agentopsy policy show
agentopsy guardian replay
```

`./install.sh --service` installs the binaries and enables the user systemd
unit when user systemd is available. `--no-service` leaves service setup off;
`--update` restarts an already-active user service after updating binaries.
The supplied unit explicitly uses `--auto-act observe`.

`health` reports derived session/database health. `service-status` is separate:
it queries the optional `agentopsyd.service` user unit and reports its
operational state without opening or changing the Agentopsy state database.

Notifications are local terminal output plus `notify-send` when available.
They can be disabled with `--no-notify` or policy/environment configuration;
cooldowns prevent repeated notices for unchanged state.

## Fail-closed provider control

`compact` and `full` are stricter control modes, not permission to act merely
because a threshold is crossed. The core blocks actions on malformed records,
identity uncertainty, unsafe/active panes, missing capabilities, missing
provider evidence, or any other ambiguity.

The only automatic native action currently supported is Codex `/compact`.
It requires all of the following for the same session:

1. exact native session, transcript, and Herdr pane identity;
2. a fresh Herdr safe-idle check immediately before the request;
3. an accepted provider/Herdr lifecycle path; and
4. matching post-request Codex lifecycle evidence and a measured context-token
   reduction.

Herdr transport acknowledgement or timeout alone never proves a compact
succeeded. Claude Code automatic control is unavailable. Automatic `/new`,
`/clear`, reset, and session rotation are unavailable for every provider.
`full` evaluates the stricter policy but cannot make those unsupported actions
available. A validated handoff is useful evidence for a future workflow, but
does not itself authorize rotation.
