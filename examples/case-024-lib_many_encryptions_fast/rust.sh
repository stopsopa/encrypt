#!/usr/bin/env bash
# case-024-lib_many_encryptions_fast, Rust library: encrypt, decrypt and update many files quickly from a program.
# The program is in rust-app/ (its own Cargo.toml, install.sh and compile.sh); the code to
# read is rust-app/src/main.rs.
cd "$(dirname "${BASH_SOURCE[0]}")"
source ../lib/demo.sh
title "case-024-lib_many_encryptions_fast [rust, library]"
source ./prepare.sh

echo "${0}: rust-app/ is a separate program; its Cargo.toml points at the library in this repository"
run 'grep "^ssenc" rust-app/Cargo.toml'
echo "${0}: download its dependencies and build it"
run_once './rust-app/install.sh'
run_once './rust-app/compile.sh'
echo "${0}: run it (source: rust-app/src/main.rs)"
run '"$(pwd)/../.target/release/case-024-demo"'
