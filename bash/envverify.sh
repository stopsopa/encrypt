#!/usr/bin/env bash
# Checks that everything the Bash implementation of ssenc needs is present and really
# works (functional probes, not version comparisons). Reports ALL problems; the exit code
# is the number of problems. Installs and changes nothing.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=checks.sh
source "$here/checks.sh"

run_checks

echo
if ((CHECK_PROBLEMS == 0)); then
  echo "bash: environment OK"
else
  echo "bash: $CHECK_PROBLEMS problem(s) found (bash/install.sh prints the commands that fix them)"
fi
exit "$CHECK_PROBLEMS"
