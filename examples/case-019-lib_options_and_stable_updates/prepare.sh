#!/usr/bin/env bash
# Sourced by rust.sh, ts.sh and bash.sh (and it can be run on its own): starts from an empty
# ./tmp, makes the demo password and an indented file.
cd "$(dirname "${BASH_SOURCE[0]}")"
declare -F run > /dev/null || source ../lib/demo.sh
rm -rf tmp && mkdir tmp

echo "${0}: prepare: a demo password and an indented file"
run 'openssl rand -base64 24 > tmp/password.txt'
run 'printf "app:\n    name: demo\n    port: 8080\n\n    nested:\n        key: value\n" > tmp/app.yml'
