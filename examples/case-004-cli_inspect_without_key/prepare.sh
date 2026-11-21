#!/usr/bin/env bash
# Sourced by rust.sh, ts.sh and bash.sh (and it can be run on its own): starts from an empty ./tmp, makes the demo password
# and two input files.
cd "$(dirname "${BASH_SOURCE[0]}")"
declare -F run > /dev/null || source ../lib/demo.sh
rm -rf tmp && mkdir tmp

echo "${0}: prepare: a demo password and two files"
run 'openssl rand -base64 24 > tmp/password.txt'
run 'printf "alpha\nbeta\n" > tmp/notes.txt'
run 'head -c 1000 /dev/urandom > tmp/data.bin'
