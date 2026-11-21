#!/usr/bin/env bash
# Checks everything the Rust implementation needs to build and reports ALL problems at
# once. Exit code = number of problems.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
problems=0

fail() { # what, problem, found, need, fix
  printf '[FAIL] %s: %s\n' "$1" "$2"
  printf '       found:  %s\n' "$3"
  printf '       need:   %s\n' "$4"
  printf '       fix:    %s\n' "$5"
  problems=$((problems + 1))
}

ok() { # what, version/details
  printf '[ OK ] %s %s\n' "$1" "$2"
}

# version_ge A B: true when dotted version A >= B (numeric fields only)
version_ge() {
  local IFS=.
  local -a a b
  read -r -a a <<<"$1"
  read -r -a b <<<"$2"
  local i x y
  for i in 0 1 2; do
    x="${a[i]:-0}"; y="${b[i]:-0}"
    x="${x%%[!0-9]*}"; y="${y%%[!0-9]*}"
    x="${x:-0}"; y="${y:-0}"
    if ((10#$x > 10#$y)); then return 0; fi
    if ((10#$x < 10#$y)); then return 1; fi
  done
  return 0
}

rustup_fix='curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh   (or, with rustup installed: rustup update stable)'

# minimum Rust version declared in Cargo.toml
msrv="$(sed -n 's/^rust-version *= *"\([0-9.]*\)".*/\1/p' "$here/Cargo.toml" | head -n 1)"
if [[ -z "$msrv" ]]; then
  fail "Cargo.toml" "no rust-version declared" "$here/Cargo.toml without a rust-version line" \
    'rust-version = "<major.minor>" in [package]' "restore rust/Cargo.toml from git: git checkout -- rust/Cargo.toml"
  msrv="0"
fi

# cargo
if cargo_path="$(command -v cargo 2>/dev/null)" && cargo_out="$(cargo --version 2>&1)"; then
  ok "cargo" "$(awk '{print $2}' <<<"$cargo_out") ($cargo_path)"
elif [[ -n "${cargo_path:-}" ]]; then
  fail "cargo" "found but does not run" "$cargo_path: $(head -n 1 <<<"$cargo_out")" "a working cargo" "$rustup_fix"
else
  fail "cargo" "not found in PATH" "nothing" "cargo (comes with Rust >= $msrv)" "$rustup_fix"
fi

# rustc
if rustc_path="$(command -v rustc 2>/dev/null)" && rustc_out="$(rustc --version 2>&1)"; then
  rustc_version="$(awk '{print $2}' <<<"$rustc_out")"
  if version_ge "$rustc_version" "$msrv"; then
    ok "rustc" "$rustc_version (>= $msrv)"
  else
    fail "rustc" "too old" "$rustc_path ($rustc_version)" "rustc >= $msrv" "rustup update stable"
  fi
elif [[ -n "${rustc_path:-}" ]]; then
  fail "rustc" "found but does not run" "$rustc_path: $(head -n 1 <<<"$rustc_out")" "rustc >= $msrv" "$rustup_fix"
else
  fail "rustc" "not found in PATH" "nothing" "rustc >= $msrv" "$rustup_fix"
fi

# C linker (rustc links through the system C compiler driver)
case "$(uname -s 2>/dev/null)" in
  Darwin) cc_fix="xcode-select --install" ;;
  Linux) cc_fix="sudo apt-get install build-essential   (or: sudo dnf install gcc / sudo apk add build-base)" ;;
  *) cc_fix="install a C toolchain (gcc or clang) that provides 'cc'" ;;
esac
if cc_path="$(command -v cc 2>/dev/null)"; then
  if cc_out="$(cc --version 2>&1)"; then
    ok "cc" "$(head -n 1 <<<"$cc_out") ($cc_path)"
  else
    fail "cc" "found but does not run" "$cc_path: $(head -n 1 <<<"$cc_out")" "a working C linker driver 'cc'" "$cc_fix"
  fi
else
  fail "cc" "C linker not found in PATH" "nothing" "a C linker driver 'cc' (gcc or clang)" "$cc_fix"
fi

# Cargo.lock must be present for the --locked builds
if [[ -f "$here/Cargo.lock" ]]; then
  ok "Cargo.lock" "present"
else
  fail "Cargo.lock" "missing" "no $here/Cargo.lock" "the committed lock file (builds use --locked)" "git checkout -- rust/Cargo.lock"
fi

exit "$problems"
