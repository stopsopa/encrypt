#!/usr/bin/env bash
# Checks that the cross-implementation tests can run: the three implementations are built,
# Playwright and its Chromium are installed, and ssh-agent tooling is present.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../scripts/verify-lib.sh
source "$here/../scripts/verify-lib.sh"
unset NODE_OPTIONS
root="$here/.."

if ! command -v node >/dev/null 2>&1; then
  fail "node: not found" "nothing on PATH" "Node.js >= 22.18 (see typescript/envverify.sh)" "asdf install nodejs"
fi

for p in rust bash typescript; do
  bin="$root/$p/bin/ssenc"
  if [[ ! -x "$bin" ]]; then
    fail "$p implementation: CLI not found" "no executable $p/bin/ssenc" "$p/bin/ssenc" "$p/compile.sh"
  elif v="$("$bin" --version 2>&1)"; then
    ok "$p CLI: $v"
  else
    fail "$p implementation: CLI does not run" "$(printf '%s' "$v" | head -1)" "'$p/bin/ssenc --version' to succeed" "$p/envverify.sh && $p/compile.sh"
  fi
done
if v="$(SSENC_TS_BUILD=js "$root/typescript/bin/ssenc" --version 2>&1)"; then ok "typescript CLI (transpiled): $v"; else
  fail "typescript transpiled build: does not run" "$(printf '%s' "$v" | head -1)" "typescript/dist/cli.js" "typescript/compile.sh"
fi
if [[ -f "$root/typescript/dist/ssenc.browser.js" ]]; then ok "browser build: typescript/dist/ssenc.browser.js"; else
  fail "browser build: missing" "no typescript/dist/ssenc.browser.js" "the transpiled browser library" "typescript/compile.sh"
fi

if [[ ! -f "$here/node_modules/playwright/package.json" ]]; then
  fail "playwright: not installed" "no tests/node_modules/playwright" "Playwright (drives the browser participant)" "tests/install.sh"
else
  pv="$(sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' "$here/node_modules/playwright/package.json" | head -1)"
  exe="$(cd "$here" && node -e 'import("playwright").then(p=>console.log(p.chromium.executablePath()))' 2>/dev/null)"
  if [[ -n "$exe" && -x "$exe" ]]; then
    ok "playwright $pv with Chromium"
  else
    fail "playwright: Chromium for version $pv is not downloaded" "${exe:-no browser path}" "the Chromium build matching Playwright $pv" "tests/install.sh   (runs: npx playwright install chromium)"
  fi
fi

for tool in ssh-agent ssh-add ssh-keygen; do
  if command -v "$tool" >/dev/null 2>&1; then ok "$tool: $(command -v "$tool")"; else
    if is_macos; then fix="comes with macOS; check PATH contains /usr/bin"; else fix="sudo apt-get install -y openssh-client"; fi
    fail "$tool: not found" "nothing on PATH" "OpenSSH client tools (the ssh tests use a private throwaway agent)" "$fix"
  fi
done

verify_finish "tests"
