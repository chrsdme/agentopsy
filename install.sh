#!/usr/bin/env sh
set -eu

PREFIX="${PREFIX:-$HOME/.local}"
BINDIR="$PREFIX/bin"

mkdir -p "$BINDIR"
install -m 0755 "$(dirname "$0")/agentopsy.py" "$BINDIR/agentopsy"

printf 'Installed Agentopsy to %s\n' "$BINDIR/agentopsy"
printf 'Ensure %s is on PATH.\n' "$BINDIR"
