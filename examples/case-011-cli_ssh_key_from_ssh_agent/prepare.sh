#!/usr/bin/env bash
# Sourced by rust.sh, ts.sh and bash.sh (and it can be run on its own): starts from an empty ./tmp, generates the demo ssh
# keys and the file to encrypt. (The ssh-agent is started by the example itself, because
# it has to live exactly as long as the example runs.)
cd "$(dirname "${BASH_SOURCE[0]}")"
declare -F run > /dev/null || source ../lib/demo.sh
rm -rf tmp && mkdir tmp

echo "${0}: prepare: demo ssh keys (an Ed25519 and an RSA one, no passphrase) and a file"
run 'ssh-keygen -q -t ed25519 -N "" -C "demo ed25519" -f tmp/demo_ed25519'
run 'ssh-keygen -q -t rsa -b 3072 -N "" -C "demo rsa" -f tmp/demo_rsa'
run 'printf "API_KEY=8f2c1d\nDB_PASSWORD=hunter2\nREGION=eu-west-1\n" > tmp/secrets.env'
