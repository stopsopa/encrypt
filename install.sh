#!/usr/bin/env bash
# Runs install.sh of every implementation and of the cross tests, one after another.
# Does not stop at the first failure: every part is attempted and a summary is printed.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
failed=()
for part in typescript rust bash tests; do
  [[ -x "$here/$part/install.sh" ]] || continue
  printf '\n=== %s/install.sh ===\n' "$part"
  "$here/$part/install.sh" || failed+=("$part")
done
echo
if ((${#failed[@]})); then
  echo "install: FAILED in: ${failed[*]}" >&2
  exit 1
fi
echo "install: all parts OK"
