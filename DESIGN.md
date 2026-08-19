# Agentopsy Design

## Principles

1. **Local first.** Session transcripts remain on the machine.
2. **Read only.** Analysis never mutates provider transcripts.
3. **Deterministic before agentic.** Metrics and defect rules should be computed directly when possible.
4. **Provider-aware, schema-normalised.** Claude and Codex logs differ, but reports should expose comparable concepts.
5. **No fake precision.** Character-based token estimates are labelled as proxies.
6. **Context health is different from code quality.** Grades describe session efficiency/risk.
7. **Evidence over folklore.** Thresholds are tunable and should evolve from measured workloads.
8. **Bounded reporting.** The analyser should summarise large logs, not reproduce them.
9. **Safe public defaults.** No real session archive, machine path, username, project name or report fixture belongs in the repository.

## Current pipeline

```text
sources
  │
  ├── live Claude stores
  ├── live/archived Codex stores
  ├── copied JSONL
  ├── copied directory
  └── ZIP archive
        │
        ▼
classify JSONL
        │
   ┌────┴────┐
   ▼         ▼
Claude     Codex
parser     parser
   │         │
   └────┬────┘
        ▼
SessionSummary
        │
        ├── common defect rules
        ├── provider-specific rules
        └── grade/score
        │
        ▼
selection
        │
        ├── filters
        ├── --session
        └── --last
        │
        ▼
render/export
```

## Selection semantics

Filters and selectors are deliberately separate.

### Filters

```text
--provider
--project
--since
--include-subagents
```

They define the eligible set.

### Selectors

```text
--session ID
--last [N]
```

They choose from the eligible set and are mutually exclusive.

### Presentation

```text
default
--sessions
--summary
```

Presentation does not change which sessions were selected.

### Exports

```text
--export
--export-claude
--export-codex
--json
```

All exports operate on the same selected set. `--summary` intentionally also changes Markdown exports to compact summary-only documents.

## Normalised session concepts

`SessionSummary` represents concepts shared across providers:

```text
identity
provider
project/cwd
start/end
activity bursts
model turns
tool calls/results
repeated reads/commands
logged token data
context pressure
compactions
subagents/delegations
defects
score/grade
```

Provider-specific fields are retained where pretending equivalence would be misleading.

## Claude parsing notes

Claude session transcripts can contain multiple streaming records associated with the same assistant request/message. Counting every JSONL record as a new model turn can therefore overcount usage. Agentopsy deduplicates assistant usage identities and prefers structured iteration telemetry when present.

Claude logs do not always provide a reliable universal context-window denominator. Agentopsy therefore uses absolute logged-request-context thresholds rather than manufacturing a percentage where the source does not support one.

## Codex parsing notes

Codex token telemetry distinguishes cumulative session totals from last-turn usage. Agentopsy uses cumulative totals for whole-session reporting and last-turn values for context-window occupancy.

Cached input is a subset of input and is reported as such rather than added again.

## Defect philosophy

A defect requires:

```text
code
severity
human message
evidence dictionary
recommendation
```

Rules should be explainable. The report must say **why** a session was flagged.

The score is useful for ranking investigation priority, not for declaring an agent "good" or "bad".

## Future live architecture

See `ROADMAP.md` for the incremental SQLite collector and Herdr integration design.
