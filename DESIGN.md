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
versioned marker scorecard
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

## v0.4 marker scoring

Marker scoring is provisional and versioned (`MARKER_SCORING_VERSION = 1`).
Each provider-applicable marker receives 5/5 (100%), 4/5 (80%), 3/5 (60%),
2/5 (40%), or 1/5 (20%) from the existing explainable defect thresholds. A
provider-unavailable marker is shown as N/A and is excluded from both lane and
overall denominators. Overall efficiency is the mean marker score expressed as
`X/100`.

The scorecard also carries an effective severity independent of that average.
In particular, a critical context-pressure condition has an `EMERGENCY` floor,
so strong results elsewhere cannot conceal it. Completed transcript summaries
are snapshots; their trend is deliberately `UNKNOWN` until rolling telemetry
can establish a direction. Reports include per-marker and lane scores, worst
indicators, and deduplicated corrective opportunities.

## v0.4 severity policy

`BEHAVIORAL_SEVERITY_POLICY_VERSION = 1` defines factory context bands from
SAFE through EMERGENCY and provisional ladders for velocity, dwell, tool
output, repetition, cache reuse, instructions, delegation, stale resumes, and
compaction. Related context pressure signals compound into an emergency rather
than being independently averaged. Terminal colour supports `--color auto`,
`always`, and `never` (plus `NO_COLOR`); text labels always convey severity.

## v0.4 causal risk

The causal engine promotes only named, observed combinations—such as repeated
reads with elevated context, large tool output with sustained turns, stale
resume with cache collapse, or compaction followed by refetch. It exposes
current/effective severity, trend, contributing lanes, causal explanations,
and a qualitative next-risk state. It never claims an unsupported token-count
forecast.

## v0.4 personal calibration

`agentopsy calibrate status|build|recommend|adopt|reset` maintains local-only,
reviewable robust profiles (P50/P75/P90/P95 and MAD). Confidence incorporates
evidence volume and stability. Profiles do not weaken factory hard safety
ceilings; adoption records an explicit local choice only.

## v0.4 historical insights

`agentopsy insights` reports recurring session-health faults, weakest markers,
and compaction/refill patterns from local aggregate state. It does not quote
transcripts, infer project history, build lineage, graph commits, or use RAG.

## v0.4 policy configuration

Policy uses versioned built-in safe defaults, SQLite runtime overrides, and
optional JSON import/export. Imports are schema-validated before a transaction
updates active state, preventing partial policy changes.

## v0.4 replay

`agentopsy guardian replay` replays local historical state through the policy
and emits deterministic severity/`WOULD_*` timeline states. It is read-only and
does not execute any provider control action.

## v0.4 control modes

Control defaults to `observe`; `compact` and `full` first enter a fail-closed
decision path. They require exact provider/session/harness mapping, a
positively supported capability, safe idle boundary, healthy integrity state,
and no critical operation. A permitted Codex compact decision may then request
the isolated control adapter; no other provider action is implied.

## v0.4 control adapters

Provider/harness control is isolated behind adapter capabilities. The v0.4
adapter supports Codex `/compact` only through an exact transcript/native
session/Herdr-pane mapping, a fresh Herdr idle re-query, and provider evidence.
Claude control is explicitly unavailable. The core never assumes a slash
command or sends blind PTY input.

## v0.4 compaction verification

Observed compactions are classified from pre/post context, reduction,
subsequent refill, repeated work, and frequency. For an automatic Codex
compact, a request is `COMPACT_VERIFIED` only after matching post-request
provider lifecycle evidence and a measured context-token reduction for the
same session. Herdr transport acknowledgement or timeout alone is never proof
of success.

## v0.4 full rotation

Full rotation requires a validated durable handoff, safe boundary, and verified
native new-session capability. Uncertainty produces `ACTION_BLOCKED`; the
handoff is preserved until a verifiable session transition succeeds.

## v0.4 fail-safe control

Parser, identity, integrity, service, telemetry, or command uncertainty fails
closed: active action is disabled for the affected scope, policy returns to
observe, and compact non-transcript integrity evidence is retained.

The incremental service accepts `--auto-act observe|compact|full` and defaults
to observe. Live checkpoint and rotation candidates reach the control decision
layer, but a transcript-derived ID is not treated as a live native-session ID.
Until an exact provider/session/pane mapping, verified idle boundary, capability,
and independently observable result are all available, compact and full are
blocked rather than sent to a provider.

## v0.4 installer/service UX

The installer updates only binaries, preserving local SQLite state and runtime
overrides. User systemd service setup is explicit (`--service`), no root is
required, and non-systemd environments receive a clear no-service result.

## v0.4 live-policy fidelity

Persisted notification enablement, severity floor, and cooldown control the
live incremental service. The display loop also has a separate same-tick
duplicate guard. THRASH requires observed frequent timing and refill,
ineffectiveness, or repeated-work evidence; absent timing does not turn a
count into a negative compaction classification. Compound context promotion is
reserved for callers with genuine independent measured lanes and is not emitted
by the current live collector.

## v0.3 implementation

The live layer keeps the retrospective parsers as the compatibility path. A
small `ProviderAdapter` boundary normalises only append-safe record facts for
the collector; it does not duplicate or replace the established report
reducers. SQLite cursors own file identity, byte offset, and incomplete-line
recovery. Health policy consumes compact derived counters and bounded evidence,
never account-quota telemetry. The optional service, notifications, Herdr
bridge, and handoff validator all operate from that local state.

## v0.4 Context Guardian foundation

Guardian signals keep three dimensions deliberately independent: `Severity`
expresses urgency, one or more `ImpactLane` values explain the affected
workflow dimensions, and `ActionSafety` describes whether an opt-in control
action is safe. A serious signal is therefore not permission to interrupt or
modify a session. Guardian evidence is limited to compact numeric/boolean
facts; transcript bodies are never stored in SQLite.

SQLite schema changes are applied as numbered, transactional migrations. A
failed migration leaves the previous schema version intact, and opening an
already-upgraded state database is idempotent.

## v0.4 rolling telemetry

The live store keeps a fixed, per-session ring of compact numeric telemetry and
hashes only. It supports five- and fifteen-minute views plus ten-, twenty-,
and fifty-turn views without retaining transcript payloads or unbounded event
history. Provider classification is cached against file identity, size/offset,
and parser version so unchanged service polls do not reopen transcript files.

## v0.4.1 execution-stream safety

Schema v5 keys derived state by `(provider, stream_id)`, while retaining the
provider-native conversation/session ID independently. Each stream records a
role (`MAIN`, `SUBAGENT`, `GUARDIAN`, or `APPROVAL_REVIEW`) and optional parent
session/stream link. A v4 upgrade invalidates source-derived rows and requires
one transactional replay from currently discoverable provider transcripts;
it never guesses stream roles from a legacy aggregate. The durable rebuild
marker fail-closes health, analytics, and control until that replay completes.
Default health, control, and
workflow analytics select `MAIN` streams; subagents and Guardian/reviewer
streams are retained for forensic inspection. File reset deletes only the
affected stream's derived facts, so sibling rollouts converge independently.

## v0.4.2 calibration applicability

Calibration records the existing provider capability for each metric. A metric
that cannot be measured with its required semantics is `UNAVAILABLE`, `N/A`,
and has no numeric baseline; it is excluded from adoption confidence checks.
For example, Claude context occupancy remains a useful absolute-token proxy,
but cannot supply a context *percentage* baseline without a universal window
denominator. Applicable metrics still require their computed confidence, and
adoption rebuilds and validates the profile against the current population.

## CLAUDE-RUNTIME-01 runtime telemetry bridge

Claude Code's status-line hook is an optional, separate source of live runtime
evidence, distinct from transcript parsing. It reports the model's raw context
capacity and current token counters directly from the running CLI, which
transcripts alone cannot provide.

**Two independent denominators.** Model context capacity
(`model_context_window_tokens` / `model_context_occupancy_pct`) and the
auto-compact operational window (`auto_compact_window_tokens` /
`auto_compact_occupancy_pct`) are never the same quantity and are represented
separately end-to-end. A 1M-token model can be configured with a 500k
auto-compact window; collapsing the two into one `context_pct` misrepresents
both. v1 only ever derives the model-capacity pair from status-line evidence;
the auto-compact pair stays `UNAVAILABLE` unless a directly trustworthy
configuration/runtime source is later added — it is never inferred from model
capacity.

**Data flow.** The status-line bridge (`agentopsy runtime bridge claude`,
installed as the `statusLine` command) reads one JSON payload from stdin,
whitelists a bounded set of fields (identity, version, model id/name, window
size, token counters — never prompts, transcript bodies, or tool output),
stamps a trusted local receipt (`receipt_ns`, generated by the bridge itself —
the incoming payload's own `observed_at` claim is never used for ordering, so
a status-line client cannot forge freshness), and atomically writes one
per-observation file under `$AGENTOPSY_STATE_DIR/claude-runtime/`, named
`<receipt_ns>-<session hash>-<nonce>.json` so concurrent writers can never
destroy each other's samples on disk. The bridge never opens SQLite. The
normal service/CLI scan loop separately reads that inbox in trusted-receipt
order (oldest first, so a regime change mid-batch applies at the right point
in the sequence), resolves each sample by **exact** `role='MAIN'` +
`session_id` + canonical `transcript_path` match against an existing Claude
session row (zero or multiple matches are rejected, never guessed — a
SUBAGENT row sharing the same identity is never resolved), and merges
resolved samples into a bounded, per-stream `service_meta` snapshot
(`claude_runtime:<stream_id>`) — not into
`sessions.current_context_tokens`/`current_context_pct`, which transcript
ingestion (`record_telemetry`) already writes unconditionally and would
silently clobber runtime evidence sharing those columns. The inbox is a
mailbox, not durable history: resolved files are deleted, unresolved ones are
retried and evicted once stale (by trusted receipt age), oversized/malformed/
symlinked/future-dated entries are quarantined on sight, and the total file
count is capped with oldest-first eviction.

**Known limitation (deferred): inbox scan work is bounded per tick, not
fair.** Directory enumeration is streamed (`os.scandir`) and capped at
`CLAUDE_RUNTIME_INBOX_SCAN_MAX_ENTRIES` entries per call, independent of and
set well above the retained-valid-sample cap
(`CLAUDE_RUNTIME_INBOX_MAX_FILES`), so a single tick can never be forced to
materialize or fully process an unbounded number of junk files. This bounds
per-tick work; it does not guarantee fairness. Under an extreme same-user
directory flood (far more entries than the scan bound in one tick), samples
beyond the enumeration window for that tick may be delayed or, in a
sufficiently sustained flood, effectively starved, since each tick only makes
bounded progress rather than guaranteeing eventual processing of every
entry. No privilege boundary is crossed by this limitation — it is same-user
denial-of-service-shaped, not an integrity or confidentiality issue. A
fair/cursor-based enumeration scheme (e.g. resuming the scan from where the
previous tick left off, rather than always starting from the same directory
position) is future work; this release deliberately does not claim guaranteed
fairness and does not implement a scan cursor.

**Occupancy numerator is input tokens only.** `model_context_occupancy_pct` =
`current_context_input_tokens / model_context_window_tokens`, where
`current_context_input_tokens` is `total_input_tokens` = `input_tokens +
cache_creation_input_tokens + cache_read_input_tokens`. `total_output_tokens`
is deliberately excluded from this numerator and tracked separately as
`reported_total_output_tokens`: Claude Code's own documented `used_percentage`
is calculated from input tokens only, so folding output tokens in here would
silently diverge from the provider's own definition of context occupancy. The
name `current_context_input_tokens` (not the earlier, ambiguous
`current_context_tokens`) makes this explicit; there is no combined
input+output field, since nothing in this feature consumes one.

**Capability is per-datum, per-session, per-version, and per-operand for
derived fields**, using the existing `ProviderCapability` enum, split into
three independently-graded tiers:

- **Identity** (`session_id`, `transcript_path`, `model_id`,
  `claude_code_version`): directly reported by a resolved status-line
  payload, always `EXACT`.
- **Model window** (`model_context_window_tokens`): `context_window_size` is a
  directly reported runtime field ("maximum context window size in tokens"),
  not derived from the historically problematic current-context counters —
  a valid direct value is `EXACT` outright, independent of
  `claude_code_version`. It is never inferred from model name, a model table,
  `autoCompactWindow`, or occupancy percentage; missing/invalid is
  `UNAVAILABLE`.
- **Current context input** (`current_context_input_tokens`): still gated on
  the small, explicitly and empirically validated set
  `CLAUDE_RUNTIME_EXACT_VERSIONS` (currently just `2.1.239`, the version this
  feature's empirical evidence was gathered against) — this is the datum with
  historical semantic-bug evidence, so self-consistency alone is never treated
  as proof of correct semantics. Reaching `EXACT` requires `current_usage` to
  be a complete four-field object (never inferred from a null value — a
  post-`/compact` null observation is accepted but never promoted, and never
  silently coerced into zero counters), the reported counters to be internally
  consistent (including a percentage cross-check against the status line's
  own rounded value), and `claude_code_version` to be in the validated set.
  That set is deliberately conservative and grows only by repeating the
  empirical validation against a new version — never by an open-ended `>=
  known-good` comparison, since a later release can silently regress the
  semantics this feature depends on. A valid-but-unvalidated version, or one
  with self-consistent but otherwise unvalidated counters, reports at most
  `OBSERVED`.

  Claude Code `2.1.239` also has an empirically observed all-zero status-line
  usage shape that Agentopsy treats as unavailable current-context evidence.
  This is a version-scoped compatibility rule, not a universal interpretation
  of zero token values.

Concretely this means two distinct field pairs are stored:
`current_context_input_tokens` / (part of) `model_context_occupancy_pct` are
the **validated** fields, populated only when eligible for `EXACT` (`None`
otherwise — never a stale value quietly left looking current);
`reported_total_input_tokens` / `reported_total_output_tokens` /
`reported_model_context_occupancy_pct` carry the raw values whenever counters
are merely self-consistent, capped at `OBSERVED`. A `last_validated_at`
timestamp is retained separately so a prior exact observation is never
confused with the current one after a later null/inconsistent sample.

**Derived fields never exceed their weakest operand.** Both
`model_context_occupancy_pct` and `reported_model_context_occupancy_pct` are
ratios of a current-context-input value over the model window, so their
capability is the weaker of the two operands' capabilities: both `EXACT` →
`EXACT`; current-context-input `OBSERVED` with an `EXACT` window → `OBSERVED`;
either operand `UNAVAILABLE` → `UNAVAILABLE`. A strong window reading can
never make a merely-observed occupancy percentage look exact.

A historical Claude session without a resolved runtime snapshot stays exactly
as before. `current_context_input_tokens`, when populated, is exact for the
session identity Claude Code reported, not a claim that the value excludes
work done by a delegated subagent — Claude's status line does not partition
delegated consumption, and empirically — validated against a captured Claude
Code 2.1.239 before/after-compaction runtime fixture — it reports the
parent/MAIN session's identity even while a subagent is actively running,
which is exactly why resolution requires `role='MAIN'` and this feature never
attempts to attribute runtime evidence to a subagent stream.
Filesystem/session discovery remains the sole authority for MAIN vs SUBAGENT
role. Peaks are tracked per telemetry **regime** — the `(model_id,
model_context_window_tokens)` pair — and reset whenever either element
changes, so a model swap under an unchanged window size, or vice versa, never
silently merges two incompatible peak measurements. This is a
telemetry-acquisition feature only: it does not change calibration adoption
semantics, Guardian thresholds, or control/auto-act behaviour, and confers no
control identity or capability. A malformed/truncated/wrong-version stored
snapshot is parsed through one centralised, never-raising validator; it is
treated as absent (never crashes ingestion, `runtime status`, or reset) and a
new valid observation can safely replace it.

**Installer** (`agentopsy integration {status,install,remove} claude`)
follows the same ownership-tracking discipline as the existing Codex
integration, with ownership proven only by a three-way agreement — parseable
ownership metadata exists, records an installed-command hash, and that hash
matches the *current* settings value exactly — never by a substring/text
match against the command (a foreign command that merely contains the text
"runtime bridge claude" is still treated as foreign). It refuses to overwrite
an existing non-Agentopsy `statusLine` with zero mutation, reinstall is
idempotent, an externally-edited Agentopsy-owned value is detected and
removal is refused rather than clobbered, and file permissions are preserved
across writes. Because `settings.json` and its ownership sidecar together
form one logical unit that two independent `os.replace` calls cannot make
atomic, both are staged (including each file's prior content and existence)
before either is published; if the second publish fails, the first is
restored exactly, so the pair is always either both updated or neither is. v1
does not implement chaining to a foreign `statusLine` command (Claude's
`statusLine` is a single command string, not a mergeable hook list); a
foreign statusLine must be removed or chained manually before installing.

## v0.4 review-debt audit

The v0.3 cached provider-classification, durable file identity, cold-start
notification recency guard, and version/report metadata are retained and
covered by regression checks. Context proxies remain explicitly labelled where
providers do not expose a trustworthy denominator; no speculative replacement
is applied.
