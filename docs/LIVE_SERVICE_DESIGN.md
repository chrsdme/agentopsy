# Agentopsy Live Service Design

## Goal

Turn the offline analyser into a near-real-time, local session-health service **without repeatedly reparsing complete Claude/Codex transcripts**.

Working name for the daemon:

```text
agentopsyd
```

The daemon remains optional. `agentopsy` continues to work as a standalone forensic CLI.

---

## Non-goals

The live service is not intended to:

- proxy model traffic;
- modify Claude/Codex transcript files;
- upload session data;
- copy whole transcripts into SQLite;
- make autonomous LLM calls;
- automatically reset sessions by default.

---

# Architecture

```text
                         append-only-ish JSONL

        Claude Code                              Codex CLI
             │                                       │
             └──────────────────┬────────────────────┘
                                │
                                ▼
                    transcript discovery/stat
                                │
                                ▼
                   per-file cursor + tail reader
                                │
                    reads only bytes > offset
                                │
                                ▼
                     provider event normaliser
                                │
                                ▼
                       incremental reducers
                                │
                ┌───────────────┼────────────────┐
                ▼               ▼                ▼
             SQLite          health FSM       notifier
                │               │                │
                │               │                ├── terminal
                │               │                ├── desktop
                │               │                └── Herdr
                │               │
                └───────┬───────┘
                        ▼
                  agentopsy CLI
                        │
                        ├── status
                        ├── summary
                        ├── trends
                        └── report
```

---

# Incremental file reading

## Why

Full rescans are acceptable for a one-off forensic command. They are wrong for a passive service.

The daemon should keep a durable cursor for each transcript:

```text
provider
path
filesystem identity
last_size
last_offset
mtime_ns
partial_line_buffer
session_id
parser_version
```

## Main loop

A cheap metadata scan can run frequently:

```text
for each known/discovered transcript:
    stat(path)

    if size == last_size:
        read 0 bytes

    if size > last_offset:
        seek(last_offset)
        read only appended bytes
        parse complete new JSONL records
        retain an incomplete trailing line for next tick
        commit new offset

    if inode/file identity changed:
        register replacement as new file generation

    if size < last_offset:
        file was truncated/replaced
        rebuild only that transcript
```

The expensive operation is therefore proportional to **new session activity**, not historical transcript size.

## Discovery

Use provider root discovery from the CLI, then remember known paths in SQLite.

Periodic directory discovery can be relatively infrequent because `stat()` and directory enumeration are cheap compared with parsing hundreds of megabytes.

---

# Normalised event layer

Provider parsers should emit small internal events rather than mutating every metric directly from raw JSON structures.

Example event types:

```text
SessionOpened
SessionMetadata
UserPrompt
ModelUsage
ContextSnapshot
ToolCalled
ToolResult
FileRead
CommandRun
Compaction
SubagentStarted
SubagentUsage
SessionReset
SessionEnded
MalformedRecord
```

Example:

```python
ContextSnapshot(
    provider="codex",
    session_id="...",
    timestamp="...",
    context_tokens=182000,
    context_window=258400,
    context_pct=0.704,
)
```

Reducers consume these events and update compact state.

---

# SQLite design

Default location:

```text
~/.local/state/agentopsy/agentopsy.db
```

Recommended pragmas:

```sql
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
PRAGMA synchronous=NORMAL;
```

## `files`

```text
id
provider
path
file_identity
size
parsed_offset
mtime_ns
partial_line
session_id
parser_version
first_seen
last_seen
```

## `sessions`

```text
session_id
provider
project
cwd
model
effort
version
started_at
last_activity_at
ended_at
model_turns
input_tokens
cached_input_tokens
cache_creation_tokens
output_tokens
reasoning_tokens
peak_context_tokens
peak_context_pct
tool_calls
tool_result_proxy_tokens
compactions
advisor_calls
subagent_count
health_state
health_score
grade
```

## `tool_aggregates`

Do not store every raw tool result.

```text
session_id
tool_name
calls
result_chars
result_tokens_proxy
max_result_chars
errors
```

## `fingerprints`

For repeated-read/command detection:

```text
session_id
kind              # command/read/etc
sha256
bounded_label
count
first_seen
last_seen
```

`bounded_label` is deliberately capped. The complete command/output does not need to become durable telemetry.

## `defects`

```text
session_id
code
severity
first_seen
last_seen
active
occurrences
bounded_evidence_json
acknowledged_until
```

## `usage_snapshots`

Keep only useful time-series resolution.

For example:

```text
session_id
ts
context_tokens
context_pct
cumulative_tokens
cached_tokens
tool_output_total
```

Old snapshots can later be downsampled instead of growing forever.

---

# Health state machine

Individual defects are useful, but a live service also needs a stable high-level state.

```text
HEALTHY
  │
  ├── warning condition
  ▼
WATCH
  │
  ├── sustained/high threshold
  ▼
CHECKPOINT_RECOMMENDED
  │
  ├── critical context / sustained waste
  ▼
ROTATION_RECOMMENDED
```

A state should not flap on every tiny change.

Use:

- entry thresholds;
- recovery thresholds;
- minimum dwell time;
- notification cooldown;
- acknowledgement/snooze state.

Example:

```text
Codex context >=65% for one sample
    -> WATCH

>=80% for N model turns or T minutes
    -> CHECKPOINT_RECOMMENDED

>=90%, or repeated compact/refetch cycle
    -> ROTATION_RECOMMENDED

context falls <55%
    -> HEALTHY
```

Actual defaults must be calibrated from real session histories.

---

# Notifications

Notifications should carry a compact reason, not a raw transcript excerpt.

Example:

```text
Agentopsy: Codex session needs attention
Context 84%, 31 snapshots >=80%, 4 post-compact re-runs.
Checkpoint recommended.
```

Notification backends:

```text
stdout/stderr
Linux notify-send
macOS local notification
Windows local notification
Herdr
custom command (explicit opt-in)
```

## Herdr notification

Current Herdr supports a direct notification command:

```bash
herdr notification show "Agentopsy" \
  --body "Claude context pressure is high; checkpoint recommended" \
  --sound request
```

Reference:

https://herdr.dev/docs/cli-reference/

---

# Herdr integration

Herdr is useful because it knows which real terminal pane contains which coding agent and can expose native session identity through integrations.

References:

- https://herdr.dev/docs/agents/
- https://herdr.dev/docs/integrations/
- https://herdr.dev/docs/agent-automation/
- https://herdr.dev/docs/socket-api/
- https://herdr.dev/docs/plugins/

## Phase A - display only

A Herdr plugin reads Agentopsy health state and provides:

```text
agentopsy current
agentopsy summary
agentopsy acknowledge
agentopsy snooze
```

It can attach small metadata to the active workspace/pane or show a notification.

## Phase B - session-ID mapping

Use Herdr's native integration metadata/session identity to map:

```text
Herdr pane
    ↕
provider + native session ID
    ↕
Agentopsy SQLite session row
```

No path guessing should be needed once native identity is available.

## Phase C - recommendation workflow

When health becomes `ROTATION_RECOMMENDED`:

```text
notify user
   ↓
optional Herdr action:
"prepare checkpoint"
   ↓
agent writes/verifies durable HANDOFF
   ↓
Herdr waits for safe lifecycle state
```

No reset yet.

## Phase D - opt-in Context Governor

Only after extensive observation:

```text
Agentopsy recommends rotation
           ↓
checkpoint requested
           ↓
handoff validated externally
           ↓
Herdr agent wait -> idle/done
           ↓
provider-specific fresh-session command
           ↓
verify session identity changed
           ↓
minimal bootstrap from durable handoff
```

The governor is a separate policy/controller layer. The analyser remains read-only.

---

# Why SQLite rather than re-reading reports

SQLite gives us:

- durable per-file byte offsets;
- instant current-session queries;
- historical trend queries;
- defect recurrence counts;
- notification deduplication/cooldowns;
- provider/project comparisons;
- no need to reconstruct history on every process start.

Example future query:

```sql
SELECT provider,
       COUNT(*) AS sessions,
       AVG(peak_context_pct) AS avg_peak_context,
       SUM(compactions) AS compactions
FROM sessions
WHERE started_at >= datetime('now', '-7 days')
GROUP BY provider;
```

---

# What a reasoning system should receive

If an external workflow-learning agent is used, give it compact derived data:

```text
30-day summary
provider/model trends
most recurrent defects
sessions with major regressions
before/after threshold changes
```

Do not hand it the complete raw transcript archive by default.

The deterministic collector should reduce hundreds of megabytes to kilobytes of high-signal evidence first.
