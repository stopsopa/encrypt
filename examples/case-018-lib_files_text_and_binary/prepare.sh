#!/usr/bin/env bash
# Sourced by rust.sh, ts.sh and bash.sh (and it can be run on its own): starts from an empty ./tmp, makes the demo password,
# a text file and a binary file.
cd "$(dirname "${BASH_SOURCE[0]}")"
declare -F run > /dev/null || source ../lib/demo.sh
rm -rf tmp && mkdir tmp

echo "${0}: prepare: a demo password, a text file and a binary file (50 000 random bytes)"
run 'openssl rand -base64 24 > tmp/password.txt'
run 'printf "database:\n    host: db.internal\n    port: 5432\n" > tmp/config.yml'
run 'head -c 50000 /dev/urandom > tmp/photo.bin'
