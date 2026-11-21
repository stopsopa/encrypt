#!/usr/bin/env bash
# Builds this example program. All examples share one build directory (examples/.target),
# so the dependencies are compiled only once; delete the export line to get the usual
# ./target directory instead.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
command -v cargo >/dev/null 2>&1 || { echo "compile.sh: cargo not found in PATH: install Rust from https://rustup.rs" >&2; exit 4; }
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$(pwd)/../../.target}"
exec cargo build --release --quiet
