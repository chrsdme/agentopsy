# Security and Privacy

## Local data sensitivity

Claude Code and Codex session transcripts can contain sensitive information, including source code, prompts, commands, output, local paths and repository names.

Agentopsy is designed to analyse those files locally and read-only.

## Network behaviour

The current Agentopsy CLI performs no intentional network requests, telemetry or model/API calls.

## Reports

Generated reports can contain local paths, repository names, command labels and other diagnostic metadata derived from the source sessions.

**Review reports before publishing or attaching them to public issues.**

## Public repository hygiene

Do not commit:

```text
real session JSONL files
session ZIP archives
generated private reports
SQLite live databases
provider credential/config secrets
```

The supplied `.gitignore` excludes common local analysis outputs, but users remain responsible for reviewing commits.

## Reporting a vulnerability

Please open a GitHub security advisory/private vulnerability report when the repository host supports it. Avoid posting secrets or private transcript content in a public issue.
