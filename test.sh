#!/usr/bin/env bash
# Runs everything: unit tests of each implementation, the cross-implementation matrix
# (including the browser through Playwright) and builds the HTML report.
# Arguments are passed to tests/run.sh, e.g.  ./test.sh --only rust,node-ts --skip-unit
set -euo pipefail
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/tests/run.sh" "$@"
