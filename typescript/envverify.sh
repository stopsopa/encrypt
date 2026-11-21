#!/usr/bin/env bash
# Checks that everything needed to compile and test the TypeScript implementation is present.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../scripts/verify-lib.sh
source "$here/../scripts/verify-lib.sh"
unset NODE_OPTIONS

NEED_NODE="22.18.0"
pinned="$(sed -n 's/^nodejs //p' "$here/../.tool-versions" 2>/dev/null)"

if ! command -v node >/dev/null 2>&1; then
  fail "node: not found" "nothing on PATH" "Node.js >= $NEED_NODE (repository pins $pinned in .tool-versions)" \
    "asdf install nodejs $pinned   (or install Node.js $pinned from https://nodejs.org)"
else
  v="$(node --version 2>/dev/null | sed 's/^v//')"
  if ! version_ge "$v" "$NEED_NODE"; then
    fail "node: too old to run TypeScript files directly" "$(command -v node) ($v)" \
      "Node.js >= $NEED_NODE (native type stripping); repository pins $pinned" "asdf install nodejs $pinned"
  else
    ok "node $v (>= $NEED_NODE)"
    if [[ -n "$pinned" && "$v" != "$pinned" ]]; then
      warn "node: version differs from .tool-versions" "found $v, repository and CI use $pinned (asdf install nodejs $pinned)"
    fi
  fi
fi

if ! command -v npm >/dev/null 2>&1; then
  fail "npm: not found" "nothing on PATH" "npm (ships with Node.js)" "reinstall Node.js: asdf install nodejs $pinned"
else
  ok "npm $(npm --version 2>/dev/null)"
fi

if [[ ! -f "$here/node_modules/typescript/package.json" ]]; then
  fail "typescript compiler: not installed" "no $here/node_modules/typescript" \
    "dev dependencies from package-lock.json" "typescript/install.sh"
else
  ok "typescript $(sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' "$here/node_modules/typescript/package.json" | head -1)"
fi

verify_finish "typescript"
