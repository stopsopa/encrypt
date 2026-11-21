#!/usr/bin/env bash
# Sourced by rust.sh, ts.sh and bash.sh (and it can be run on its own): starts from an empty ./tmp, generates a demo password,
# a demo ssh key, a text file and a binary file.
cd "$(dirname "${BASH_SOURCE[0]}")"
declare -F run > /dev/null || source ../lib/demo.sh
rm -rf tmp && mkdir tmp

echo "${0}: prepare: a demo password, a demo ssh key, a text file and a binary file"
run 'openssl rand -base64 24 > tmp/password.txt'
run 'ssh-keygen -q -t ed25519 -N "" -C "demo ed25519" -f tmp/demo_ed25519'
run 'printf "host: db.internal\nport: 5432\nuser: admin\n" > tmp/config.yml'
run 'head -c 100000 /dev/urandom > tmp/photo.bin'
