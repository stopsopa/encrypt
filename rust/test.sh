#!/usr/bin/env bash
# Unit tests and the shared known-answer vectors (../tests/vectors).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
exec cargo test --release --locked "$@"
