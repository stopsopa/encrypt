#!/usr/bin/env bash
# Sourced by rust.sh, ts.sh and bash.sh (and it can be run on its own): starts from an empty ./tmp, makes the demo password,
# a binary file and a text file.
cd "$(dirname "${BASH_SOURCE[0]}")"
declare -F run > /dev/null || source ../lib/demo.sh
rm -rf tmp && mkdir tmp

echo "${0}: prepare: a demo password in a file"
run 'openssl rand -base64 24 > tmp/password.txt'

echo "${0}: prepare: a binary file (200 000 random bytes) and a small text file"
run 'head -c 200000 /dev/urandom > tmp/photo.bin'
run 'printf "line one\nline two\nline three\n" > tmp/notes.txt'
