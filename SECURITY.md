# Security and Privacy

## Local data sensitivity

Claude Code and Codex session transcripts can contain sensitive information, including source code, prompts, commands, output, local paths and repository names.

Agentopsy analyses those files locally and read-only. The optional Codex
control path is separate, explicitly requested through service mode, and does
not modify provider transcripts.

## Network behaviour

The current Agentopsy CLI performs no intentional network requests, telemetry or model/API calls.

## Reports

Generated reports can contain local paths, repository names, command labels and other diagnostic metadata derived from the source sessions. The default
SQLite state stores derived aggregates, bounded evidence/hashes, and
short-lived identity metadata; it does not store transcript bodies by default.

**Review reports before publishing or attaching them to public issues.**

## Public repository hygiene

Do not commit:

```text
real session JSONL files
session ZIP archives
generated private reports
SQLite live databases
provider credential/config secrets
private native session or pane identifiers
```

The supplied `.gitignore` excludes common local analysis outputs, but users remain responsible for reviewing commits.

## Reporting a vulnerability

Please open a GitHub security advisory/private vulnerability report when the repository host supports it. Avoid posting secrets or private transcript content in a public issue.

## Control safety

`observe` is the safe default. Codex automatic `/compact` is available only
with exact identity, Herdr mapping, fresh safe-idle state, and provider-confirmed
context reduction. Ambiguity fails closed. Claude automatic control and
automatic `/new`, `/clear`, reset, and rotation remain unavailable.
