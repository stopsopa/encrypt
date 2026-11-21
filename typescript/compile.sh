#!/usr/bin/env bash
# Builds the four single-file libraries and the CLI into dist/, then typechecks them:
#   dist/ssenc.node.ts     dist/ssenc.node.js      Node.js
#   dist/ssenc.browser.ts  dist/ssenc.browser.js   browsers (typechecked WITHOUT Node types)
#   dist/cli.ts            dist/cli.js
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
unset NODE_OPTIONS
node scripts/bundle.mjs
npx tsc -p tsconfig.json
npx tsc -p tsconfig.browser.json
echo "typescript: typecheck OK (node build with Node types, browser build without)"
