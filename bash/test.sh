#!/usr/bin/env bash
# Unit tests of the Bash implementation: runs every test/*.sh, which print one line per
# test ("ok   - ..." / "FAIL - ..."), then prints a summary. Non-zero exit on any failure.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here" || exit 1

if ((BASH_VERSINFO[0] < 4)); then
  echo "bash: tests need bash >= 4.0, this is $BASH_VERSION (run bash/envverify.sh)" >&2
  exit 1
fi

log="$(mktemp "${TMPDIR:-/tmp}/ssenc-test-log.XXXXXX")"
trap 'rm -f "$log"' EXIT
failed_files=0
for t in test/*.sh; do
  echo "# $t"
  bash "$t" 2>&1 | tee -a "$log"
  if ((PIPESTATUS[0] != 0)); then failed_files=$((failed_files + 1)); fi
done

pass=$(grep -c '^ok   - ' "$log")
fail=$(grep -c '^FAIL - ' "$log")
skip=$(grep -c '^skip - ' "$log")
echo
echo "bash: $pass passed, $fail failed, $skip skipped"
if ((fail > 0 || failed_files > 0)); then
  echo "bash: tests FAILED"
  exit 1
fi
echo "bash: tests OK"
