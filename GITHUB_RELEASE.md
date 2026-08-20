# GitHub Release Checklist

Use this checklist for a reviewed release from the intended release commit.
It is a process aid, not a substitute for project-specific release gates.

## Before publishing

1. Verify the target branch, expected commit, working-tree cleanliness, remote
   relationship, and that the intended version tag/release do not already
   exist.
2. Update only authoritative release metadata and review its diff.
3. Run `make quick`, `make full`, `python3 -m compileall -q .`, and
   `git diff --check` on the release commit.
4. Build the wheel, install it in an isolated environment, and verify
   `agentopsy --version` reports the exact release version.
5. Confirm no private transcripts, session identifiers, credentials, local
   SQLite state, reports, `local_only` material, or generated provider
   worktrees are tracked.
6. Fast-forward the reviewed release branch to `main` only when ancestry and
   remote state are understood; do not rewrite history or force push.
7. Push `main`, verify `main` equals `origin/main`, then create and push an
   annotated tag at that exact commit.

## Release notes

State what is available and what is deliberately unavailable. For v0.4:

- `observe` is the safe default.
- Codex automatic `/compact` requires exact identity, Herdr mapping, safe
  idle, provider lifecycle verification, and context reduction; ambiguity
  fails closed.
- Claude automatic control, automatic `/new`, `/clear`, and rotation are not
  enabled; `full` does not change that.
- Do not include private local session IDs or transcript excerpts.

Create a release only from an already-pushed verified tag (for GitHub CLI,
use `gh release create <tag> --verify-tag`). Verify the published title, tag,
target commit, and capability wording afterwards.

## After publishing

Fetch tags and verify `HEAD`, `origin/main`, and the annotated release tag all
resolve to the validated commit. Perform one final package-install smoke test
when practical. Keep any operational release log under ignored `local_only/`.
