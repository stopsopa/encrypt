#!/usr/bin/env bash
# case-022-lib_ssh_agent_keys, Rust library: ssh keys held by ssh-agent as keys: by public key, by fingerprint, together with a password.
# The program is in rust-app/ (its own Cargo.toml, install.sh and compile.sh); the code to
# read is rust-app/src/main.rs.
cd "$(dirname "${BASH_SOURCE[0]}")"
source ../lib/demo.sh
title "case-022-lib_ssh_agent_keys [rust, library]"
source ./prepare.sh

echo "${0}: a private ssh-agent just for this example (your own agent is never used), with both demo keys loaded"
demo_agent_start
run 'ssh-add -q tmp/demo_ed25519 tmp/demo_rsa'
run 'ssh-add -l'

echo "${0}: rust-app/ is a separate program; its Cargo.toml points at the library in this repository"
run 'grep "^ssenc" rust-app/Cargo.toml'
echo "${0}: download its dependencies and build it"
run_once './rust-app/install.sh'
run_once './rust-app/compile.sh'
echo "${0}: run it (source: rust-app/src/main.rs)"
run '"$(pwd)/../.target/release/case-022-demo"'
