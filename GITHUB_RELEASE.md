# GitHub Release Notes / Publishing Checklist

## Suggested repository name

```text
agentopsy
```

## Suggested description

> Local forensic session-health analyser for Claude Code and Codex CLI. Finds context bloat, stale resumes, compaction thrash, repeated reads/commands, and tool-output waste.

## Suggested topics

```text
claude-code
codex
coding-agents
agent-observability
context-window
token-usage
session-analysis
local-first
python
developer-tools
```

## Suggested initial release

Title:

```text
Agentopsy v0.2.0 - first public release
```

Release body:

```markdown
Agentopsy is a local, read-only forensic session-health analyser for Claude Code and OpenAI Codex CLI.

Highlights:
- automatic Claude/Codex session-store discovery
- ZIP/directory/JSONL analysis
- context, cache, tool-output and activity-burst analysis
- stale-session reuse detection
- compaction/refetch and repetition flags
- `--sessions`, `--session`, `--last`, and `--summary`
- combined and provider-specific Markdown exports
- JSON output
- zero third-party runtime dependencies
- no API key, model calls, telemetry, or transcript uploads

This release also documents the planned incremental SQLite service and optional Herdr integration. Automatic session rotation is not enabled by default.
```

## Before pushing

```bash
python -m py_compile agentopsy.py
python -m unittest discover -s tests -v
./agentopsy.py --help
```

Review repository contents:

```bash
find . -maxdepth 3 -type f | sort
```

Check that no real logs/reports were accidentally added:

```bash
find . -type f \
  \( -name '*.jsonl' -o -name '*.db' -o -name '*.zip' \) \
  -print
```

Check staged files before first commit:

```bash
git status --short
git diff --cached
```

## Suggested first commit

```text
feat: release Agentopsy v0.2.0
```

## GitHub settings

Recommended:

- enable Issues;
- enable private vulnerability reporting/security advisories if available;
- protect the default branch once CI is proven;
- require the `tests` workflow before merging pull requests;
- do not enable any telemetry or hosted transcript upload as part of the default project.
