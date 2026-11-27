#!/usr/bin/env bash
# Unit tests and the shared known-answer vectors (../tests/vectors), then the end-to-end test of
# "ssenc --update" (tests/update.sh, with releases faked in a local directory).
# With arguments (a filter of cargo test, e.g. ./test.sh sums) only cargo test runs.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
cargo test --release --locked "$@"
if (($# == 0)); then
  /bin/bash tests/update.sh
fi
