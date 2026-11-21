#!/usr/bin/env bash
# Shared helpers for the envverify.sh scripts. Source it, call ok/fail/warn, end with
# verify_finish. Every problem is reported (never stop at the first one); the exit code is
# the number of problems.
VERIFY_PROBLEMS=0

ok() { printf '[ OK ] %s\n' "$1"; }

warn() { # warn <what> <detail>
  printf '[WARN] %s\n       %s\n' "$1" "$2"
}

fail() { # fail <what: problem> <found> <need> <fix>
  VERIFY_PROBLEMS=$((VERIFY_PROBLEMS + 1))
  printf '[FAIL] %s\n       found:  %s\n       need:   %s\n       fix:    %s\n' "$1" "$2" "$3" "$4"
}

# version_ge A B  ->  true when dotted version A >= B
version_ge() {
  local IFS=. i a b
  read -r -a a <<<"$1"
  read -r -a b <<<"$2"
  for ((i = 0; i < ${#b[@]}; i++)); do
    local x="${a[i]:-0}" y="${b[i]:-0}"
    x="${x%%[!0-9]*}"; y="${y%%[!0-9]*}"
    if ((10#${x:-0} > 10#${y:-0})); then return 0; fi
    if ((10#${x:-0} < 10#${y:-0})); then return 1; fi
  done
  return 0
}

is_macos() { [[ "$(uname -s)" == "Darwin" ]]; }

verify_finish() { # verify_finish <name>
  if ((VERIFY_PROBLEMS == 0)); then
    printf '%s: environment OK\n' "$1"
  else
    printf '%s: %d problem(s) found\n' "$1" "$VERIFY_PROBLEMS" >&2
  fi
  exit "$VERIFY_PROBLEMS"
}
