#!/usr/bin/env bash
# Runs compile.sh of every implementation and of the cross tests, one after another.
# Does not stop at the first failure: every part is attempted and a summary is printed.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
failed=()
for part in typescript rust bash tests; do
  [[ -x "$here/$part/compile.sh" ]] || continue
  printf '\n=== %s/compile.sh ===\n' "$part"
  "$here/$part/compile.sh" || failed+=("$part")
done
echo
if ((${#failed[@]})); then
  echo "compile: FAILED in: ${failed[*]}" >&2
  exit 1
fi
echo "compile: all parts OK"
