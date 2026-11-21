#!/usr/bin/env bash
# Entry point of the cross-implementation tests.
#
#   tests/run.sh [--only rust,bash,node-ts,node-js,browser-js] [--skip-unit] [--suite cross,vectors,rekey,diff,negative]
#
# 1. starts a private throwaway ssh-agent with the test keys (never touches your own agent)
# 2. runs tests/run.ts (stages 0-4, see that file)
# 3. always builds the report, also after failures:  tests/out/report/index.html
# Exit code: 0 only if every planned check passed.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
unset NODE_OPTIONS SSENC_PASSWORD SSENC_NEW_PASSWORD

log() { printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }

log "starting the throwaway test ssh-agent"
agent="$("$here/lib/agent.sh" start)" || { log "tests/run.sh: could not start the test ssh-agent" >&2; exit 4; }
eval "$agent"
trap '"$here/lib/agent.sh" stop' EXIT

node --disable-warning=ExperimentalWarning "$here/run.ts" "$@"
status=$?

node --disable-warning=ExperimentalWarning "$here/report/build.ts" || status=1
if [[ "$status" == 0 ]]; then log "tests passed"; else log "tests FAILED (exit code $status)"; fi
exit "$status"
