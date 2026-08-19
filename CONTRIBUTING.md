# Contributing

Contributions should preserve Agentopsy's core properties:

- local first;
- read only against provider session logs;
- deterministic where practical;
- no mandatory external services;
- no real/private transcript fixtures in the repository;
- provider-specific assumptions isolated and documented;
- token proxies clearly labelled as proxies.

## Development checks

```bash
python -m py_compile agentopsy.py
python -m unittest discover -s tests -v
```

## Test fixtures

Use synthetic JSONL records created inside temporary directories. Never commit a real user's Claude/Codex transcript to reproduce a bug.

If a real log exposes a parser issue, minimise it manually to the smallest synthetic structure needed to reproduce the problem.

## New defect rules

A new rule should include:

1. a stable defect code;
2. severity;
3. concrete evidence;
4. a human-readable explanation;
5. an actionable recommendation;
6. at least one focused test when practical.

Avoid rules that merely encode personal preference without measurable evidence.
