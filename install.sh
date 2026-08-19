#!/usr/bin/env sh
set -eu

UPDATE=0; SERVICE=0
for arg in "$@"; do case "$arg" in --update) UPDATE=1;; --service) SERVICE=1;; --no-service) SERVICE=0;; *) echo "Usage: $0 [--update] [--service] [--no-service]" >&2; exit 2;; esac; done
PREFIX="${PREFIX:-$HOME/.local}"; BINDIR="$PREFIX/bin"; ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

mkdir -p "$BINDIR"
install -m 0755 "$ROOT/agentopsy.py" "$BINDIR/agentopsy"
ln -sf agentopsy "$BINDIR/agentopsyd"

printf 'Installed agentopsy and agentopsyd to %s\n' "$BINDIR"
case ":${PATH}:" in *":$BINDIR:"*) ;; *) printf 'PATH does not include %s; add it to your shell configuration if appropriate.\n' "$BINDIR";; esac
if [ "$SERVICE" -eq 1 ]; then
  if command -v systemctl >/dev/null 2>&1 && systemctl --user show-environment >/dev/null 2>&1; then
    UNIT="$HOME/.config/systemd/user/agentopsyd.service"; mkdir -p "$(dirname "$UNIT")"
    sed "s|ExecStart=.*|ExecStart=$BINDIR/agentopsyd run|" "$ROOT/docs/agentopsyd.service" > "$UNIT"
    systemctl --user daemon-reload; systemctl --user enable --now agentopsyd.service; systemctl --user is-active --quiet agentopsyd.service
  else echo 'User systemd is unavailable; binaries installed without service.' >&2; fi
elif [ "$UPDATE" -eq 1 ] && command -v systemctl >/dev/null 2>&1 && systemctl --user is-active --quiet agentopsyd.service 2>/dev/null; then systemctl --user restart agentopsyd.service; fi
"$BINDIR/agentopsy" --version
