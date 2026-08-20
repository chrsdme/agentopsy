# Contributing

Contributions should preserve Agentopsy's core properties:

- local first;
- read only against provider session logs;
- deterministic where practical;
- no mandatory external services;
- no real/private transcript fixtures in the repository;
- provider-specific assumptions isolated and documented;
- token proxies clearly labelled as proxies.
- unavailable telemetry shown as N/A/UNAVAILABLE, never silently as zero.

## Development checks

```bash
make quick
make full
python3 -m compileall -q .
git diff --check
```

## Test fixtures

Use synthetic JSONL records created inside temporary directories. Never commit a real user's Claude/Codex transcript to reproduce a bug.

If a real log exposes a parser issue, minimise it manually to the smallest synthetic structure needed to reproduce the problem.

Do not include local session IDs, transcript excerpts, paths, database state,
or credentials in a public issue, fixture, commit, or release note.

## New defect rules

A new rule should include:

1. a stable defect code;
2. severity;
3. concrete evidence;
4. a human-readable explanation;
5. an actionable recommendation;
6. at least one focused test when practical.

Avoid rules that merely encode personal preference without measurable evidence.

## Control and service changes

Preserve `observe` as the safe default. A control change must have focused
tests for missing/ambiguous identity, unsafe lifecycle state, unavailable
capability, and failed provider verification. Missing evidence must block the
action rather than trigger a best-effort terminal interaction. Do not claim
that a provider supports `/compact`, `/new`, `/clear`, or rotation without
empirical, end-to-end evidence for that exact operation.
