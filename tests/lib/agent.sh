#!/usr/bin/env bash
# Starts a private, throwaway ssh-agent holding the repository's test keys and prints
# shell assignments for it:
#
#     eval "$(tests/lib/agent.sh start)"     # sets SSH_AUTH_SOCK, SSH_AGENT_PID, SSENC_AGENT_DIR
#     tests/lib/agent.sh stop                # kills it and removes its directory
#
# It never talks to the developer's own agent: SSH_AUTH_SOCK is replaced before any key
# is added, and the script refuses to continue if the new agent did not come up.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
keys="$here/../keys"

case "${1:-}" in
  start)
    # Unix socket paths are limited to ~104 bytes, so use a short directory.
    dir="$(mktemp -d /tmp/ssenc.XXXXXX)"
    out="$(ssh-agent -a "$dir/a" -s)" || { echo "agent.sh: could not start ssh-agent" >&2; rm -rf "$dir"; exit 4; }
    eval "$out" >/dev/null
    # shellcheck disable=SC2064
    trap "kill $SSH_AGENT_PID 2>/dev/null; rm -rf '$dir'" ERR
    if [[ "${SSH_AUTH_SOCK:-}" != "$dir/a" || ! -S "$dir/a" ]]; then
      echo "agent.sh: throwaway ssh-agent did not start on $dir/a" >&2
      rm -rf "$dir"
      exit 4
    fi
    printf '#!/bin/sh\necho ssenc-test\n' > "$dir/askpass"
    chmod 700 "$dir/askpass"
    for k in test_ed25519 test_rsa test_ecdsa; do
      cp "$keys/$k" "$dir/$k"
      chmod 600 "$dir/$k"
      SSH_ASKPASS="$dir/askpass" SSH_ASKPASS_REQUIRE=force DISPLAY="${DISPLAY:-:0}" \
        ssh-add -q "$dir/$k" </dev/null >&2
      rm -f "$dir/$k"
    done
    echo "export SSH_AUTH_SOCK='$SSH_AUTH_SOCK'"
    echo "export SSH_AGENT_PID='$SSH_AGENT_PID'"
    echo "export SSENC_AGENT_DIR='$dir'"
    ;;
  stop)
    if [[ -n "${SSENC_AGENT_DIR:-}" && "${SSH_AUTH_SOCK:-}" == "$SSENC_AGENT_DIR/a" ]]; then
      kill "$SSH_AGENT_PID" 2>/dev/null || true
      rm -rf "$SSENC_AGENT_DIR"
    else
      echo "agent.sh: refusing to stop: this is not the throwaway test agent" >&2
      exit 4
    fi
    ;;
  *)
    echo "usage: agent.sh start|stop" >&2
    exit 1
    ;;
esac
