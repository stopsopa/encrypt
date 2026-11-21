#!/usr/bin/env bash
# Sourced by rust.sh, ts.sh and bash.sh (and it can be run on its own): starts from an empty
# ./tmp, generates two demo ssh keys and a backup password. (The ssh-agent is started by the
# example itself, because it has to live exactly as long as the example runs.)
cd "$(dirname "${BASH_SOURCE[0]}")"
declare -F run > /dev/null || source ../lib/demo.sh
rm -rf tmp && mkdir tmp

echo "${0}: prepare: demo ssh keys (Ed25519 and RSA, no passphrase) and a backup password"
run 'ssh-keygen -q -t ed25519 -N "" -C "demo ed25519" -f tmp/demo_ed25519'
run 'ssh-keygen -q -t rsa -b 3072 -N "" -C "demo rsa" -f tmp/demo_rsa'
run 'openssl rand -base64 24 > tmp/backup-password.txt'
