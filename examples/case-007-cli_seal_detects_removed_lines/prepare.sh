#!/usr/bin/env bash
# Sourced by rust.sh, ts.sh and bash.sh (and it can be run on its own): starts from an empty ./tmp, makes the demo password
# and the file to encrypt.
cd "$(dirname "${BASH_SOURCE[0]}")"
declare -F run > /dev/null || source ../lib/demo.sh
rm -rf tmp && mkdir tmp

echo "${0}: prepare: a demo password and a file with four lines"
run 'openssl rand -base64 24 > tmp/password.txt'
run 'printf "allow: alice\nallow: bob\ndeny: mallory\nallow: carol\n" > tmp/rules.txt'
