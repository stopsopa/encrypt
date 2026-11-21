#!/usr/bin/env bash
# Downloads the exact dependency versions pinned in Cargo.lock (nothing is compiled).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
exec cargo fetch --locked
