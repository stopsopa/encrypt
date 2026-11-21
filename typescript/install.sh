#!/usr/bin/env bash
# Installs the development dependencies (TypeScript compiler, Node type definitions).
# The library itself has no runtime dependencies.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
unset NODE_OPTIONS
npm ci --no-audit --no-fund
