#!/usr/bin/env bash
# case-018-lib_files_text_and_binary, Rust library: encrypt a text file line by line and a binary file as a blob, inspect and decrypt them.
# The program is in rust-app/ (its own Cargo.toml, install.sh and compile.sh); the code to
# read is rust-app/src/main.rs.
cd "$(dirname "${BASH_SOURCE[0]}")"
source ../lib/demo.sh
title "case-018-lib_files_text_and_binary [rust, library]"
source ./prepare.sh

echo "${0}: rust-app/ is a separate program; its Cargo.toml points at the library in this repository"
run 'grep "^ssenc" rust-app/Cargo.toml'
echo "${0}: download its dependencies and build it"
run_once './rust-app/install.sh'
run_once './rust-app/compile.sh'
echo "${0}: run it (source: rust-app/src/main.rs)"
run '"$(pwd)/../.target/release/case-018-demo"'
