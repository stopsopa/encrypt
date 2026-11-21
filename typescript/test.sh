#!/usr/bin/env bash
# Unit tests of the TypeScript implementation (all four dist files).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
unset NODE_OPTIONS
node --disable-warning=ExperimentalWarning --test test/*.test.ts
