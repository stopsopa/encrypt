#!/usr/bin/env bash
# Helpers shared by the unit tests in this directory. Sourced by every test/*.sh.
# Each test prints one line: "ok   - name" or "FAIL - name"; t_done prints the totals.
# shellcheck disable=SC2034

set -u
export LC_ALL=C
T_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
T_ROOT="$(cd "$T_HERE/../.." && pwd)"
T_VECTORS="$T_ROOT/tests/vectors"
T_KEYS="$T_ROOT/tests/keys"
T_SSENC="$T_HERE/../bin/ssenc"
# shellcheck source=../ssenc.sh
source "$T_HERE/../ssenc.sh"

T_PASS=0
T_FAIL=0
T_TMP="$(mktemp -d "${TMPDIR:-/tmp}/ssenc-test.XXXXXX")"
t_cleanup() { rm -rf "$T_TMP"; }
trap t_cleanup EXIT

# Cheap Argon2id cost for everything that is not a known-answer vector.
T_KDF="m=64,t=1,p=1"

t_ok() {
  T_PASS=$((T_PASS + 1))
  printf 'ok   - %s\n' "$1"
}

t_fail() {
  T_FAIL=$((T_FAIL + 1))
  printf 'FAIL - %s\n' "$1"
  if [[ -n ${2:-} ]]; then printf '       %s\n' "$2"; fi
}

t_eq() { # NAME ACTUAL EXPECTED
  if [[ $2 == "$3" ]]; then
    t_ok "$1"
  else
    t_fail "$1" "got '${2:0:200}', expected '${3:0:200}'"
  fi
}

# t_same NAME FILE-ACTUAL FILE-EXPECTED. The actual file is removed afterwards so that a
# later test can never pass on the left-over output of an earlier one.
t_same() {
  if cmp -s "$2" "$3"; then
    t_ok "$1"
  else
    t_fail "$1" "files differ (or missing): $2 $3"
  fi
  if [[ $2 == "$T_TMP"/* && $2 != "$T_TMP"/in/* ]]; then rm -f "$2"; fi
}

# t_code NAME EXPECTED-EXIT COMMAND... : also requires that nothing went to stdout on error
t_code() {
  local name=$1 want=$2 rc
  shift 2
  "$@" >"$T_TMP/code.out" 2>"$T_TMP/code.err"
  rc=$?
  if ((rc != want)); then
    t_fail "$name" "exit code $rc, expected $want ($(head -n 1 "$T_TMP/code.err"))"
  elif ((want != 0)) && [[ -s $T_TMP/code.out ]]; then
    t_fail "$name" "wrote output although it failed"
  elif ((want != 0)) && ! grep -q '^ssenc: [A-Z]*: ' "$T_TMP/code.err"; then
    t_fail "$name" "stderr is not 'ssenc: <KIND>: <message>': $(head -n 1 "$T_TMP/code.err")"
  else
    t_ok "$name"
  fi
}

t_done() {
  printf '# %s: %d passed, %d failed\n' "$(basename "$0")" "$T_PASS" "$T_FAIL"
  ((T_FAIL == 0))
}

# Reads tests/vectors/vectors.json (pretty-printed by JSON.stringify) without jq:
# fills V_NAME[], V_KIND[] (password | ssh) and V_KEY[].
t_load_vectors() {
  local line name=
  V_NAME=() V_KIND=() V_KEY=()
  while IFS= read -r line; do
    case $line in
      *'"name": "'*)
        name=${line#*'"name": "'}
        name=${name%'"'*}
        ;;
      *'"password": "'* | *'"ssh": "'*)
        V_NAME+=("$name")
        if [[ $line == *'"password": "'* ]]; then V_KIND+=(password); else V_KIND+=(ssh); fi
        line=${line#*'": "'}
        V_KEY+=("${line%'"'*}")
        ;;
    esac
  done <"$T_VECTORS/vectors.json"
}
