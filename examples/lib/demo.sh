# shellcheck shell=bash
# Sourced by every example script (rust.sh, ts.sh, bash.sh). It only provides the small
# helpers that make an example print what it does; the commands of an example are all
# written out in the example itself. Explanations are plain: echo "${0}: text".
#
#   title TEXT            headline of the example
#   run 'COMMAND'         prints the command, then executes it in this shell
#   timed 'COMMAND'       the same, and prints how long it took
#   fails CODE 'COMMAND'  the same, for a command that is supposed to fail with exit code CODE
#   check TEXT 'COMMAND'  silent assertion: the example stops when COMMAND is not true
#   built FILE HOW        stops with a clear message when FILE was not built yet
#   run_once 'COMMAND'    like run, for a build step that examples.sh already did (see below)
#   demo_agent_start      starts a private ssh-agent for the example (stopped on exit)

set -euo pipefail

# Nothing from the caller's session may leak into an example: no debugger options for
# node, no password, and above all not the developer's own ssh-agent. Examples that need
# an agent start a private one with demo_agent_start.
unset NODE_OPTIONS SSENC_PASSWORD SSENC_NEW_PASSWORD SSH_AUTH_SOCK SSH_AGENT_PID

if [[ -t 1 ]]; then
  _DEMO_BOLD=$'\033[1m' _DEMO_GREEN=$'\033[32m' _DEMO_RED=$'\033[31m' _DEMO_OFF=$'\033[0m'
else
  _DEMO_BOLD='' _DEMO_GREEN='' _DEMO_RED='' _DEMO_OFF=''
fi

title() { printf '\n%s##### %s #####%s\n' "$_DEMO_BOLD" "$*" "$_DEMO_OFF"; }

run() {
  printf '$ %s\n' "$1"
  eval "$1"
}

# Seconds since the epoch with fractions (bash 3.2 has no built-in for it).
_demo_now() { perl -MTime::HiRes=time -e 'printf "%.3f", time'; }

timed() {
  local start end
  printf '$ %s\n' "$1"
  start="$(_demo_now)"
  eval "$1"
  end="$(_demo_now)"
  printf '    (took %s s)\n' "$(perl -e 'printf "%.2f", $ARGV[1] - $ARGV[0]' "$start" "$end")"
}

_demo_kind() {
  case "$1" in
    0) echo "success" ;; 1) echo "USAGE" ;; 2) echo "AUTH" ;; 3) echo "MALFORMED" ;; 4) echo "ENV" ;; *) echo "?" ;;
  esac
}

fails() {
  local want="$1" got=0
  printf '$ %s\n' "$2"
  set +e
  eval "$2"
  got=$?
  set -e
  if [[ "$got" == "$want" ]]; then
    printf '%s    -> exit code %s (%s), as expected%s\n' "$_DEMO_GREEN" "$got" "$(_demo_kind "$got")" "$_DEMO_OFF"
  else
    printf '%sEXAMPLE FAILED: expected exit code %s (%s), got %s%s\n' "$_DEMO_RED" "$want" "$(_demo_kind "$want")" "$got" "$_DEMO_OFF" >&2
    exit 1
  fi
}

check() {
  if eval "$2" >/dev/null 2>&1; then
    printf '%s    ok: %s%s\n' "$_DEMO_GREEN" "$1" "$_DEMO_OFF"
  else
    printf '%sEXAMPLE FAILED: %s%s\n    %s\n' "$_DEMO_RED" "$1" "$_DEMO_OFF" "$2" >&2
    exit 1
  fi
}

# examples.sh checks what is built and builds the Rust example programs once, before it
# runs the examples, and then exports SSENC_EXAMPLES_PREPARED=1. With that variable set,
# `built` and `run_once` do nothing again. An example started directly does all of it itself.
built() {
  if [[ -n "${SSENC_EXAMPLES_PREPARED:-}" ]]; then return 0; fi
  if [[ ! -e "$1" ]]; then
    printf '%sEXAMPLE CANNOT RUN: %s does not exist. Build it first: %s%s\n' "$_DEMO_RED" "$1" "$2" "$_DEMO_OFF" >&2
    exit 4
  fi
}

run_once() {
  if [[ -n "${SSENC_EXAMPLES_PREPARED:-}" ]]; then
    printf '$ %s    (skipped: examples.sh did it once for all examples)\n' "$1"
    return 0
  fi
  run "$1"
}

# Starts an ssh-agent that belongs to this example only and points SSH_AUTH_SOCK at it.
# The example then adds its demo keys with ssh-add. The agent is killed and its directory
# removed when the example ends, also when it fails.
demo_agent_start() {
  command -v ssh-agent >/dev/null 2>&1 || { echo "EXAMPLE CANNOT RUN: ssh-agent not found in PATH (install OpenSSH)" >&2; exit 4; }
  # Socket paths are limited to about 100 bytes, so the directory must be short.
  DEMO_AGENT_DIR="$(mktemp -d /tmp/ssenc-demo.XXXXXX)"
  DEMO_AGENT_PID=''
  trap demo_agent_stop EXIT
  printf '$ eval "$(ssh-agent -a %s/agent.sock -s)"\n' "$DEMO_AGENT_DIR"
  local out
  out="$(ssh-agent -a "$DEMO_AGENT_DIR/agent.sock" -s)"
  eval "$out" >/dev/null
  if [[ "${SSH_AUTH_SOCK:-}" != "$DEMO_AGENT_DIR/agent.sock" || ! -S "$SSH_AUTH_SOCK" ]]; then
    echo "EXAMPLE CANNOT RUN: the private ssh-agent did not start" >&2
    exit 4
  fi
  DEMO_AGENT_PID="$SSH_AGENT_PID"
}

demo_agent_stop() {
  if [[ -n "${DEMO_AGENT_PID:-}" ]]; then kill "$DEMO_AGENT_PID" 2>/dev/null || true; fi
  if [[ -n "${DEMO_AGENT_DIR:-}" ]]; then rm -rf "$DEMO_AGENT_DIR"; fi
}
