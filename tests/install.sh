#!/usr/bin/env bash
# Installs what the cross-implementation tests need: Playwright and its Chromium.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
unset NODE_OPTIONS
npm ci --no-audit --no-fund
if [[ -n "${CI:-}" && "$(uname -s)" == "Linux" ]]; then
  npx playwright install --with-deps chromium
else
  npx playwright install chromium
fi
