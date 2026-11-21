#!/usr/bin/env bash
# Sourced by rust.sh, ts.sh and bash.sh (and it can be run on its own): starts from an empty
# ./tmp and makes an old and a new demo password.
cd "$(dirname "${BASH_SOURCE[0]}")"
declare -F run > /dev/null || source ../lib/demo.sh
rm -rf tmp && mkdir tmp

echo "${0}: prepare: an old and a new demo password"
run 'openssl rand -base64 24 > tmp/old-password.txt'
run 'openssl rand -base64 24 > tmp/new-password.txt'
