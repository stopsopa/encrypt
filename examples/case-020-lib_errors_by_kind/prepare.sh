#!/usr/bin/env bash
# Sourced by rust.sh, ts.sh and bash.sh (and it can be run on its own): starts from an empty
# ./tmp, makes the demo password and an ssh key that is loaded in no agent.
cd "$(dirname "${BASH_SOURCE[0]}")"
declare -F run > /dev/null || source ../lib/demo.sh
rm -rf tmp && mkdir tmp

echo "${0}: prepare: a demo password and an ssh key that is not loaded anywhere"
run 'openssl rand -base64 24 > tmp/password.txt'
run 'ssh-keygen -q -t ed25519 -N "" -C "demo key" -f tmp/demo_ed25519'
