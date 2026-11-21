#!/usr/bin/env bash
# Sourced by rust.sh, ts.sh and bash.sh (and it can be run on its own): starts from an empty ./tmp, makes the demo password
# and the file that will be encrypted, edited and encrypted again.
cd "$(dirname "${BASH_SOURCE[0]}")"
declare -F run > /dev/null || source ../lib/demo.sh
rm -rf tmp && mkdir tmp

echo "${0}: prepare: a demo password and a file with six lines"
run 'openssl rand -base64 24 > tmp/password.txt'
run 'printf "host: db.internal\nport: 5432\nuser: admin\npassword: hunter2\ntimeout: 30\nretries: 3\n" > tmp/config.yml'
