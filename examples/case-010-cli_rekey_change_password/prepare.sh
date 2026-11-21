#!/usr/bin/env bash
# Sourced by rust.sh, ts.sh and bash.sh (and it can be run on its own): starts from an empty ./tmp, makes the old and the
# new demo password and the file to encrypt.
cd "$(dirname "${BASH_SOURCE[0]}")"
declare -F run > /dev/null || source ../lib/demo.sh
rm -rf tmp && mkdir tmp

echo "${0}: prepare: an old password, a new password and a file"
run 'openssl rand -base64 24 > tmp/old-password.txt'
run 'openssl rand -base64 24 > tmp/new-password.txt'
run 'printf "host: db.internal\nuser: admin\npassword: hunter2\n" > tmp/config.yml'
