# Agentopsy

**Forensic session health for coding agents.**

Agentopsy is a local, read-only analyser for **Claude Code** and **OpenAI Codex CLI** session transcripts. It shows how sessions grow, where context and tool output accumulate, when agents repeatedly re-read or re-run work, and which sessions deserve investigation before the same habits become expensive workflow patterns.

It is not another hosted dashboard and it does not need an API key. Agentopsy parses the session logs already on your machine, produces compact terminal/Markdown/JSON reports, and sends **nothing** to a model or external service.

## Context Guardian signal registry

v0.4 records provider capability explicitly: absent telemetry is never treated
as zero or as a negative health signal. Inspect the versioned registry and any
signal's measurement limits locally:

```bash
agentopsy signals
agentopsy explain SESSION_CONTEXT_OCCUPANCY
```

Provider capabilities are `EXACT`, `OBSERVED`, `PROXY`, `PARTIAL`, or
`UNAVAILABLE`. Extension/startup material is classified conservatively as
`ALWAYS_LOADED`, `LAZY_LOADED`, `EVENT_LOADED`, or `UNKNOWN` only when evidence
is actually observable.

```text
Claude Code logs ─┐
                  ├──> Agentopsy ──> summaries / session health / defects
Codex CLI logs ───┘                      │
                                         ├──> Markdown / JSON
                                         └──> future live health service
```

## Why Agentopsy?

A coding-agent session can succeed and still be inefficient. Common failure patterns include:

- carrying a very large context through hundreds of later turns;
- resuming an old, bloated session after hours or days;
- repeatedly reading the same files;
- dumping large command or test output into the main context;
- compacting and then immediately rebuilding the discarded context;
- excessive repeated commands or verification loops;
- large always-loaded instruction payloads;
- advisor/subagent activity that adds significant hidden work;
- letting a session live far beyond a sensible checkpoint.

Agentopsy turns those patterns into explicit metrics and defect flags.

> A bad Agentopsy grade is a **workflow-health signal**, not a statement that the code produced by the session is bad.

---

## Supported agents

### Claude Code

Agentopsy auto-discovers:

```text
$CLAUDE_CONFIG_DIR/projects
```

or, when `CLAUDE_CONFIG_DIR` is not set:

```text
~/.claude/projects
```

### OpenAI Codex CLI

Agentopsy auto-discovers:

```text
$CODEX_HOME/sessions
$CODEX_HOME/archived_sessions
```

or, by default:

```text
~/.codex/sessions
~/.codex/archived_sessions
```

It can also analyse:

- an individual `.jsonl` session;
- an exported directory;
- a ZIP archive;
- multiple `--source` paths in one run.

---

## Requirements

- Python **3.10+**
- No third-party Python dependencies
- Linux, macOS, or Windows with Python available

---

## Quick start

### Run directly

```bash
chmod +x agentopsy.py
./agentopsy.py
```

### Install for the current user

```bash
./install.sh
agentopsy --version
```

The installer copies the single executable to:

```text
~/.local/bin/agentopsy
```

Make sure `~/.local/bin` is on your `PATH`.

### Install as a Python project

```bash
python -m pip install .
agentopsy --version
```

---

# CLI guide

## Default report

With no switches, Agentopsy discovers both providers and prints:

1. source inventory;
2. provider totals;
3. session health ranking;
4. detailed findings for the worst sessions.

```bash
agentopsy
```

Analyse a copied archive instead:

```bash
agentopsy --source sessions.zip
```

---

## `--summary`

Print **only compact provider totals** for the current selection.

```bash
agentopsy --summary
```

Example shape:

```text
1. Claude
────────────────────────────────────────────────
12 sessions
~2.4k unique model iterations
~420.0M logged model-token work
~398.0M cache-read tokens
~740.0k tool-result proxy tokens
18 advisor calls
6 attached subagents
highest logged request/advisor context: ~310.0k

2. Codex
────────────────────────────────────────────────
9 sessions
~210.0M cumulative logged tokens
~207.0M input
~193.0M cached-input subset
~2.8M output
11 compactions
highest context occupancy: 88.4%
tool-output generated/proxy: ~8.2M
```

`--summary` also changes Markdown exports to **summary-only** reports:

```bash
agentopsy --summary --export weekly-summary.md
```

---

## `--sessions`

Print only a copy-friendly list of session IDs and dates:

```bash
agentopsy --sessions
```

Shape:

```text
#   Provider  Date/Time                 Session ID
----------------------------------------------------------------------------------------
1   claude   2026-08-18 19:10 UTC      aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
2   codex    2026-08-18 18:42 UTC      019f0000-1111-2222-3333-444444444444
```

Use this when you want to copy an ID for `--session`.

---

## `--session ID`

Analyse only a specific session:

```bash
agentopsy --session aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
```

Unique prefixes are accepted:

```bash
agentopsy --session aaaaaaaa
```

If the prefix matches multiple session IDs, Agentopsy stops and asks for a more specific prefix.

`--session` is repeatable:

```bash
agentopsy \
  --session aaaaaaaa \
  --session 019f0000 \
  --summary
```

---

## `--last [N]`

Analyse the most recent session **per selected provider**:

```bash
agentopsy --last
```

With both providers enabled, this selects:

```text
latest Claude session
+
latest Codex session
```

Select the latest three sessions per provider:

```bash
agentopsy --last 3
```

Provider filtering composes naturally:

```bash
agentopsy --provider claude --last 3
agentopsy --provider codex --last --summary
```

`--session` and `--last` are intentionally mutually exclusive.

---

# Export switches

Exports operate on the **same final selection** shown in the terminal.

## `--export FILE`

Write one Markdown file containing all selected providers:

```bash
agentopsy --export report.md
```

With a selector:

```bash
agentopsy --last 2 --export latest.md
agentopsy --session aaaaaaaa --export session.md
```

With compact output:

```bash
agentopsy --summary --export summary.md
```

`--markdown FILE` is retained as a compatibility alias for `--export FILE`.

## `--export-claude FILE`

Write only the Claude subset:

```bash
agentopsy --export-claude claude-report.md
```

## `--export-codex FILE`

Write only the Codex subset:

```bash
agentopsy --export-codex codex-report.md
```

All three can be combined:

```bash
agentopsy \
  --last 3 \
  --export combined.md \
  --export-claude claude.md \
  --export-codex codex.md
```

Or combined with summary mode:

```bash
agentopsy \
  --summary \
  --export combined-summary.md \
  --export-claude claude-summary.md \
  --export-codex codex-summary.md
```

## JSON export

Machine-readable output remains available separately:

```bash
agentopsy --last 5 --json report.json
```

---

# Selection logic

Agentopsy applies arguments in a predictable order:

```text
1. discover/read sources
          │
2. --provider / --project / --since / subagent policy
          │
3. --session OR --last
          │
4. console mode: default / --summary / --sessions
          │
5. --export / --export-claude / --export-codex / --json
```

Examples:

```bash
# Latest Claude session, compact terminal summary and Markdown summary
agentopsy --provider claude --last --summary --export claude-latest.md

# Find IDs, then inspect one session deeply
agentopsy --sessions
agentopsy --session aaaaaaaa

# Last two sessions from each provider, full provider-specific exports
agentopsy --last 2 \
  --export-claude recent-claude.md \
  --export-codex recent-codex.md

# Only sessions from a project name/path fragment during the last week
agentopsy --project my-project --since 7d --summary
```

---

# What Agentopsy measures

## Common

- session ID, provider, version, model and effort;
- project/CWD metadata;
- wall-clock span and active bursts;
- longest activity burst;
- largest idle gap;
- user prompts and model turns;
- tool calls and tool-result volume;
- largest individual tool result;
- repeated commands;
- repeated file/path reads;
- malformed transcript lines;
- health score and A-F workflow grade.
- a provisional, versioned 5-point marker scorecard with lane and overall
  efficiency scores; unavailable provider telemetry is N/A rather than a
  penalty, and severe context conditions retain an explicit severity floor.
- accessible severity bands and compound behavioural-risk policy; use
  `--color auto`, `--color always`, `--color never`, or `NO_COLOR`.
- explainable causal-risk promotions, qualitative trend, contributing lanes,
  and predicted next risk state without speculative token forecasts.
- local, reviewable robust calibration: `agentopsy calibrate status`, `build`,
  `recommend`, `adopt`, and `reset`; factory safety ceilings remain in force.

## Claude Code

- deduplicates repeated assistant streaming records;
- uses `usage.iterations` where available;
- separates normal message iterations from advisor iterations;
- tracks cache read/create and output telemetry;
- estimates request-context pressure per iteration;
- counts iterations at `>=150k` logged request context;
- detects high-context dwell;
- identifies large unscoped `Read` results;
- tracks `/clear` and `/new` records when visible;
- aggregates attached Claude subagent metadata/usage;
- reports persisted-output sidecars separately rather than assuming they entered model context.

## Codex CLI

- parses rollout/session metadata and token-count events;
- uses cumulative `total_token_usage` for session totals;
- uses `last_token_usage` for context-window occupancy;
- treats `cached_input_tokens` as a subset of input rather than double-counting it;
- tracks context-window occupancy;
- tracks compactions;
- detects exact command re-runs shortly after compaction;
- detects duplicate token snapshots;
- measures persisted startup/instruction payloads;
- tracks delegation/spawn calls;
- uses Codex's reported original output token count when available, otherwise a labelled character proxy.

---

# Defect flags

Current rules include:

```text
LONG_GAP_REUSE
STALE_SESSION_REUSE
LONG_ACTIVE_BURST
VERY_LONG_ACTIVE_BURST
LARGE_TOOL_RESULT
GIANT_TOOL_RESULT
HIGH_TOOL_OUTPUT_VOLUME
TOOL_OUTPUT_FLOOD
COMMAND_REPETITION
REPEATED_READ
MALFORMED_LOG_LINES

CLAUDE_COSTLY_CONTEXT
CLAUDE_VERY_HIGH_CONTEXT
CLAUDE_EXTREME_CONTEXT
CLAUDE_HIGH_CONTEXT_DWELL
UNSCOPED_LARGE_READ
UNSCOPED_LARGE_READS
ADVISOR_CONTEXT_MULTIPLIER
MANY_MODEL_TURNS
EXCESSIVE_MODEL_TURNS

CODEX_CONTEXT_PRESSURE
CODEX_CONTEXT_HIGH
CODEX_CONTEXT_CRITICAL
CODEX_HIGH_CONTEXT_DWELL
COMPACTION_THRASH
POST_COMPACT_REFETCH
DUPLICATE_TOKEN_EVENTS
LARGE_STARTUP_INSTRUCTIONS
HEAVY_STARTUP_INSTRUCTIONS
```

Thresholds are intentionally conservative starting points. They should evolve from real-world evidence rather than pretending there is one perfect context percentage for every model and workload.

---

# Privacy and safety

Agentopsy is designed to be **local-first and read-only**:

- no API key required;
- no model calls;
- no telemetry;
- no network requests;
- no transcript modification;
- ZIP archives are materialised only into a temporary directory while being analysed.

However, your **source transcripts are sensitive**. They can contain:

- source code;
- user prompts;
- shell commands and output;
- local paths/usernames;
- repository names;
- error messages;
- content returned by tools.

Generated reports can also contain paths and selected diagnostic snippets/command labels. **Review a report before posting it publicly.**

The Git repository should never contain real user session archives or generated personal reports.

See [SECURITY.md](SECURITY.md).

---

# Incremental/live mode

The forensic CLI remains independent. The optional local service adds durable,
incremental state without changing provider transcripts:

```bash
# one safe incremental pass
agentopsy service once

# run passively (20 seconds by default)
agentopsyd run --foreground --interval 20

# inspect derived local state
agentopsy health
agentopsy health --all
agentopsy health --provider claude
agentopsy trends --days 7
agentopsy trends --json
agentopsy handoff /path/to/project
```

State is stored at `~/.local/state/agentopsy/agentopsy.db`; set
`AGENTOPSY_STATE_DIR` or pass `--state-dir` to use another location. A sample
user service is [docs/agentopsyd.service](docs/agentopsyd.service). Copy it to
`~/.config/systemd/user/`, then enable it yourself if desired; the installer
does not enable services.

The live policy defaults are deliberately provisional: watch at 50%, checkpoint
at 65%, and rotation recommendation at 80%, with recovery below 45%. Codex
uses reported context-window occupancy. Claude lacks a universal denominator,
so its live band is explicitly a conservative context-token proxy. Subscription
or account quota is never used as a rotation signal.

The service emits terminal notifications and uses `notify-send` when available.
Notifications can be disabled with `--no-notify`; repeated events are cooled
down. Environment configuration is available for unattended runs:
`AGENTOPSY_NOTIFICATIONS=off`, `AGENTOPSY_NOTIFICATION_MIN_SEVERITY=high`,
`AGENTOPSY_NOTIFICATION_PROVIDERS=claude`, and
`AGENTOPSY_NOTIFICATION_SESSIONS=<id,...>`. Herdr is optional and passive in this release. No automatic `/clear`,
`/new`, reset, or rotation is performed.

## Legacy polling mode

The older full-rescan prototype remains available for compatibility:

```bash
agentopsy --watch 300
```

It periodically regenerates:

```text
~/.local/state/agentopsy/latest.md
~/.local/state/agentopsy/latest.json
```

This mode is useful for experimentation but rescans complete files; prefer the
incremental service for ongoing observation.

See [ROADMAP.md](ROADMAP.md) and [docs/LIVE_SERVICE_DESIGN.md](docs/LIVE_SERVICE_DESIGN.md).

---

# Live architecture

```text
Claude / Codex JSONL
       │ append only
       ▼
Agentopsy collector
  ├── remembers inode/path + byte offset
  ├── reads only appended bytes
  ├── normalises high-signal events
  └── stores aggregates in SQLite
       │
       ├──────────> CLI / trend reports
       │
       ├──────────> desktop / Herdr notifications
       │
       └──────────> optional Herdr context governor
```

Unchanged files are `stat()`ed only; grown files are sought from their persisted
offset; truncated/replaced files safely rebuild just that file. SQLite stores
derived counters and bounded fingerprints, not transcript bodies.

---

# Herdr direction

The intended Herdr integration is initially **observational**:

```text
Agentopsy health event
      │
      ├── context pressure
      ├── giant tool output
      ├── stale-session reuse
      └── compaction/refetch loop
      │
      ▼
Herdr notification / pane metadata
```

Later, after thresholds have been calibrated, a separate opt-in governor can:

```text
recommend checkpoint
      ↓
request HANDOFF.md
      ↓
wait until agent is safe/idle
      ↓
start a fresh session
      ↓
bootstrap from compact durable state
```

Automatic session rotation should **not** be the default behavior of the analyser.

---

# Repository layout

```text
agentopsy/
├── agentopsy.py
├── README.md
├── ROADMAP.md
├── DESIGN.md
├── CHANGELOG.md
├── SECURITY.md
├── CONTRIBUTING.md
├── docs/
│   └── LIVE_SERVICE_DESIGN.md
├── LICENSE
├── pyproject.toml
├── install.sh
├── .gitignore
├── contrib/
│   └── agentopsy-watch.service.example
└── tests/
    └── test_agentopsy.py
```

---

# Tests

Fast deterministic checks during focused work:

```bash
make quick
```

Release/full checks:

```bash
make full
```

```bash
python -m unittest discover -s tests -v
```

Run a syntax check:

```bash
python -m py_compile agentopsy.py
```

---

# Status

`v0.2.0` is intended as the first clean public release candidate:

- Claude Code + Codex support;
- automatic store discovery;
- ZIP/directory/file analysis;
- session defect detection;
- provider summaries;
- session selection;
- Markdown/JSON export;
- zero third-party runtime dependencies.

See [CHANGELOG.md](CHANGELOG.md) and [ROADMAP.md](ROADMAP.md).

---

# Disclaimer

Agentopsy is an independent open-source project. It is not affiliated with, endorsed by, or maintained by Anthropic, OpenAI, or Herdr.

# Known limitations

- Provider transcript schemas can change between Claude Code/Codex releases. Parser updates may be required.
- Claude context figures are based on logged request/context telemetry. Agentopsy does not invent a percentage when the transcript lacks a trustworthy context-window denominator.
- Character-to-token calculations are labelled `proxy` and are not billing claims.
- Codex cumulative token totals and last-turn/context values are intentionally treated differently.
- Health thresholds are heuristics intended for investigation and calibration, not universal limits.
- A resumed-session flag proves that one transcript became active again after an idle gap. It does not, by itself, identify the UI setting or human action that caused the resume.

# Upstream documentation

- Claude Code data usage and local transcripts: https://docs.anthropic.com/en/docs/claude-code/data-usage
- Codex troubleshooting and session-log locations: https://developers.openai.com/codex/reference/troubleshooting
- Herdr agent automation: https://herdr.dev/docs/agent-automation/
- Herdr socket API: https://herdr.dev/docs/socket-api/
- Herdr plugin model: https://herdr.dev/docs/plugins/
