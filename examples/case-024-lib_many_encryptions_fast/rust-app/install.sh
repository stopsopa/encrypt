#!/usr/bin/env bash
# Downloads the dependencies of this example program (nothing is compiled).
# The lock file starts as a copy of the library's own, so the example builds with exactly
# the dependency versions the library is tested with.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
command -v cargo >/dev/null 2>&1 || { echo "install.sh: cargo not found in PATH: install Rust from https://rustup.rs" >&2; exit 4; }
[[ -f Cargo.lock ]] || cp ../../../rust/Cargo.lock Cargo.lock
exec cargo fetch --quiet
