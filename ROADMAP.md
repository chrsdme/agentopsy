# Agentopsy Roadmap

This roadmap keeps the project split into two layers:

1. **forensic analyser**, deterministic and read-only;
2. **live health service**, incremental and optionally integrated with Herdr.

The analyser should remain useful by itself even if the service is never installed.

## v0.2 - Public CLI foundation

- [x] Claude Code transcript discovery/parsing
- [x] Codex transcript + archived-session discovery/parsing
- [x] ZIP/directory/file sources
- [x] provider summaries
- [x] `--sessions`
- [x] `--session ID`
- [x] `--last [N]`
- [x] `--summary`
- [x] `--export`
- [x] `--export-claude`
- [x] `--export-codex`
- [x] JSON export
- [x] defect flags and health grades
- [x] privacy/public-release scrub
- [x] synthetic tests only in repository

## v0.3 - Incremental collector (`agentopsyd`)

The service must **not rescan entire transcripts on every interval**.

### File cursor model

For every discovered transcript store:

```text
provider
path
filesystem device/inode or stable identity
last observed size
last parsed byte offset
mtime_ns
session_id
parser version
```

On each lightweight scan:

```text
stat file
  │
  ├── unchanged size -> do nothing
  │
  ├── larger -> seek(last_offset), parse appended bytes only
  │
  ├── inode changed -> treat as replacement/new file
  │
  └── size < offset -> transcript truncated/replaced, rebuild only that file
```

A normal tick should therefore read **zero bytes** for unchanged sessions and only the newly appended tail for active sessions.

### SQLite state

Default database target:

```text
~/.local/state/agentopsy/agentopsy.db
```

Proposed tables:

```text
files
sessions
usage_snapshots
tool_aggregates
defects
notifications
service_meta
```

SQLite should run locally with WAL mode. Raw transcript content should **not** be copied into the database by default. Store metrics, hashes, bounded labels and file references instead.

### Bounded evidence

The service should avoid becoming another source of data bloat:

- hash repeated commands/reads;
- keep bounded previews only where diagnostically useful;
- cap evidence arrays per defect;
- store aggregate counters instead of raw tool output;
- make raw-content retention an explicit opt-in, not a default.

## v0.4 - Live health and notifications

Introduce stateful session-health policies with hysteresis/cooldowns.

Potential events:

```text
CONTEXT_PREPARE
CONTEXT_HIGH
CONTEXT_CRITICAL
HIGH_CONTEXT_DWELL
GIANT_TOOL_RESULT
TOOL_OUTPUT_FLOOD
REPEATED_READ_LOOP
COMMAND_REPETITION_LOOP
COMPACTION_THRASH
POST_COMPACT_REFETCH
STALE_SESSION_RESUMED
```

Example policy:

```text
context reaches prepare threshold
        ↓
record warning once
        ↓
remain quiet until state changes materially
        ↓
context reaches high threshold
        ↓
notify
        ↓
context falls below recovery threshold
        ↓
clear warning state
```

This avoids screaming every two seconds while a session remains above one threshold.

### Notification backends

Keep notification adapters optional and local:

- terminal stderr/status line;
- Linux `notify-send` when installed;
- macOS Notification Center adapter;
- Windows notification adapter;
- Herdr notification adapter;
- optional generic command/webhook adapter, disabled by default.

No outbound network destination should be enabled silently.

## v0.5 - Herdr plugin

Herdr is a strong host for the live layer because it already owns the coding-agent terminals. The plugin should consume Agentopsy's small SQLite/JSON health state rather than re-reading raw transcripts.

Proposed responsibilities:

```text
Agentopsy                    Herdr
---------                    -----
parse transcript             know active pane/agent
measure context              know agent lifecycle state
score health                 show notifications
recommend action      --->   associate health with pane
                              optionally trigger workflow
```

Initial plugin features:

- show health grade/context pressure beside detected Claude/Codex agents;
- notification when a session crosses configured health thresholds;
- command to open the latest Agentopsy summary;
- command to analyse the current agent's native session ID;
- command to acknowledge/snooze a warning;
- no automatic `/clear` by default.

## v0.6 - Opt-in Context Governor

Only after real-world threshold calibration.

State machine:

```text
NORMAL
  ↓
PREPARE
  ↓
ROTATION_RECOMMENDED
  ↓
CHECKPOINT_REQUESTED
  ↓
HANDOFF_VERIFIED
  ↓
WAITING_SAFE
  ↓
ROTATE
  ↓
VERIFY_FRESH_SESSION
  ↓
BOOTSTRAP
  ↓
NORMAL
```

Hard safety requirements:

- never interrupt an agent while it is actively modifying/running critical work;
- never equate threshold crossing with permission to clear immediately;
- never let the LLM be the sole authority that its reset succeeded;
- never destroy the previous durable handoff until the new session is verified;
- default to recommendation/notification mode;
- require explicit opt-in for automated rotation.

## v0.7 - Trends and workflow learning

Longitudinal queries from SQLite:

```text
median/peak context by provider/model/project
cache amplification over time
compactions per productive hour
repeated-read rate
repeated-command rate
tool-output pressure
session duration distributions
defect recurrence
health grade trend
rotation outcome comparison
```

This is the layer another workflow-learning or agent-operations system could consume.

The preferred flow is:

```text
raw transcripts
     ↓
Agentopsy deterministic metrics
     ↓
few-KB trend summary
     ↓
optional reasoning agent
     ↓
proposed workflow/skill/hook improvements
```

Do not feed hundreds of megabytes of raw histories into an LLM merely to discover aggregate patterns that Python/SQLite can calculate exactly.

## Additional providers

Potential future parser adapters:

- Hermes Agent
- Gemini CLI
- OpenCode
- other local coding-agent harnesses with inspectable logs

Provider support should use a stable normalized event model rather than spreading provider-specific assumptions throughout the analyser.
