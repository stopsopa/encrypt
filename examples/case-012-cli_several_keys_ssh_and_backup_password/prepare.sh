#!/usr/bin/env bash
# Sourced by rust.sh, ts.sh and bash.sh (and it can be run on its own): starts from an empty ./tmp, generates three demo ssh
# keys (one of an unsupported type), a backup password and the file to encrypt.
cd "$(dirname "${BASH_SOURCE[0]}")"
declare -F run > /dev/null || source ../lib/demo.sh
rm -rf tmp && mkdir tmp

echo "${0}: prepare: demo ssh keys of two people, an ECDSA key, a backup password and a file"
run 'ssh-keygen -q -t ed25519 -N "" -C "alice" -f tmp/alice_ed25519'
run 'ssh-keygen -q -t rsa -b 3072 -N "" -C "bob" -f tmp/bob_rsa'
run 'ssh-keygen -q -t ecdsa -N "" -C "carol" -f tmp/carol_ecdsa'
run 'openssl rand -base64 24 > tmp/backup-password.txt'
run 'printf "API_KEY=8f2c1d\nDB_PASSWORD=hunter2\n" > tmp/secrets.env'
