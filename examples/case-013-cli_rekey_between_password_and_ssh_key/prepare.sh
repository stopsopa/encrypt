#!/usr/bin/env bash
# Sourced by rust.sh, ts.sh and bash.sh (and it can be run on its own): starts from an empty ./tmp, generates two demo ssh
# keys, two passwords and the file to encrypt.
cd "$(dirname "${BASH_SOURCE[0]}")"
declare -F run > /dev/null || source ../lib/demo.sh
rm -rf tmp && mkdir tmp

echo "${0}: prepare: demo ssh keys, passwords and a file"
run 'ssh-keygen -q -t ed25519 -N "" -C "demo ed25519" -f tmp/demo_ed25519'
run 'ssh-keygen -q -t rsa -b 3072 -N "" -C "demo rsa" -f tmp/demo_rsa'
run 'openssl rand -base64 24 > tmp/password.txt'
run 'openssl rand -base64 24 > tmp/backup-password.txt'
run 'printf "API_KEY=8f2c1d\nDB_PASSWORD=hunter2\n" > tmp/secrets.env'
