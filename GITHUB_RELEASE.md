# GitHub Release Checklist

Use this checklist for a reviewed release from the intended release commit.
It is a process aid, not a substitute for project-specific release gates.

## Before publishing

1. Verify clean `main`, `main == origin/main`, expected ancestry, and that the
   intended version is consistent in runtime and package metadata.
2. Review README, CHANGELOG, ROADMAP, and validation documentation; run
   `make quick`, `make full`, `python3 -m compileall -q .`, and `git diff --check`.
3. Run the public project test suite and verify the release build before
   publishing; then confirm GitHub CI is green across the supported matrix.
4. Build the wheel, install it in an isolated environment, and verify
   `agentopsy --version` reports the exact release version.
5. Confirm no private transcripts, session identifiers, credentials, local
   SQLite state, reports, `local_only` material, or generated provider
   worktrees are tracked.
6. Push reviewed `main`, verify `main == origin/main`, then create and push an
   annotated tag at that exact commit. Create a GitHub release only from that
   pushed, verified tag.

## Release notes

State what is available and what is deliberately unavailable. For v0.6.1,
cover runtime compatibility, StateStore cleanup, and the CI tag/full-history
fix. State that schema 6, parser 1, and Claude runtime format 2 are unchanged,
and that EVPROV-001 remains a known XFAIL. Do not include private local session
identifiers or transcript excerpts.

Create a release only from an already-pushed verified tag (for GitHub CLI,
use `gh release create <tag> --verify-tag`). Verify the published title, tag,
target commit, and capability wording afterwards.

## After publishing

Fetch tags and verify `HEAD`, `origin/main`, and the annotated release tag all
resolve to the validated commit. Perform one final package-install smoke test
when practical. Keep any operational release log under ignored `local_only/`.
