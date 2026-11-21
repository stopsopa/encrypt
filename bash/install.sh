#!/usr/bin/env bash
# The Bash implementation has nothing to build or download. This script installs NOTHING:
# it runs the checks of envverify.sh and prints the package-manager command for everything
# that is missing, for you to run. Exit code 0 when nothing is missing, 1 otherwise.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=checks.sh
source "$here/checks.sh"

report="$(run_checks)"
# run_checks ran in a subshell above (to keep its report quiet); run it again for the counters
run_checks >/dev/null

if ((CHECK_PROBLEMS == 0)); then
  echo "bash: nothing to install - every required tool is present and working."
else
  echo "bash: $CHECK_PROBLEMS problem(s). Nothing was installed. Details:"
  echo
  printf '%s\n' "$report" | sed -n '/^\[FAIL\]/,/^       fix:/p'
  echo
  echo "Run the following yourself, then run bash/envverify.sh again:"
  echo
  for cmd in "${CHECK_FIXES[@]}"; do
    printf '    %s\n' "$cmd"
  done
fi
if ((${#CHECK_OPTIONAL[@]} > 0)); then
  echo
  echo "Optional (not required to run ssenc):"
  echo
  for cmd in "${CHECK_OPTIONAL[@]}"; do
    printf '    %s\n' "$cmd"
  done
fi
((CHECK_PROBLEMS == 0))
