#!/usr/bin/env bash
# "Compiles" the Bash implementation: there is nothing to build, so this is a syntax check
# (bash -n) of every script plus shellcheck when it is installed (findings fail the run).
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here" || exit 1

files=(ssenc.sh bin/ssenc checks.sh envverify.sh install.sh compile.sh test.sh)
for f in test/*.sh test/*.bash; do
  [[ -f $f ]] && files+=("$f")
done

failed=0
for f in "${files[@]}"; do
  if [[ ! -f $f ]]; then
    echo "[FAIL] bash -n $f: file is missing"
    failed=$((failed + 1))
  elif out=$(bash -n "$f" 2>&1); then
    echo "[ OK ] bash -n $f"
  else
    echo "[FAIL] bash -n $f"
    printf '%s\n' "$out" | sed 's/^/       /'
    failed=$((failed + 1))
  fi
done

if command -v shellcheck >/dev/null 2>&1; then
  if shellcheck -x -P SCRIPTDIR -s bash "${files[@]}"; then
    echo "[ OK ] shellcheck (${#files[@]} files)"
  else
    echo "[FAIL] shellcheck reported findings"
    failed=$((failed + 1))
  fi
else
  echo "[SKIP] shellcheck is not installed - only the syntax was checked (bash/install.sh prints how to get it)"
fi

if ((failed)); then
  echo "bash: compile FAILED ($failed)"
  exit 1
fi
echo "bash: compile OK"
