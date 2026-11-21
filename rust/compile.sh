#!/usr/bin/env bash
# Builds target/release/ssenc, which bin/ssenc runs.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
exec cargo build --release --locked
