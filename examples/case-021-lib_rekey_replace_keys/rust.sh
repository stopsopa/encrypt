#!/usr/bin/env bash
# case-021-lib_rekey_replace_keys, Rust library: replace the keys of an encrypted text, with or without a new data key.
# The program is in rust-app/ (its own Cargo.toml, install.sh and compile.sh); the code to
# read is rust-app/src/main.rs.
cd "$(dirname "${BASH_SOURCE[0]}")"
source ../lib/demo.sh
title "case-021-lib_rekey_replace_keys [rust, library]"
source ./prepare.sh

echo "${0}: rust-app/ is a separate program; its Cargo.toml points at the library in this repository"
run 'grep "^ssenc" rust-app/Cargo.toml'
echo "${0}: download its dependencies and build it"
run_once './rust-app/install.sh'
run_once './rust-app/compile.sh'
echo "${0}: run it (source: rust-app/src/main.rs)"
run '"$(pwd)/../.target/release/case-021-demo"'
