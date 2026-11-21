#!/usr/bin/env bash
# Sourced by rust.sh, ts.sh and bash.sh (and it can be run on its own): starts from an empty ./tmp, makes the demo password
# and the file that will be encrypted.
cd "$(dirname "${BASH_SOURCE[0]}")"
declare -F run > /dev/null || source ../lib/demo.sh
rm -rf tmp && mkdir tmp

echo "${0}: prepare: a demo password in a file"
run 'openssl rand -base64 24 > tmp/password.txt'

echo "${0}: prepare: the file to encrypt"
cat > tmp/config.yml <<'END_OF_FILE'
database:
    host: db.internal
    port: 5432
    user: admin
    password: hunter2

features:
    - search
    - export
END_OF_FILE
run 'cat tmp/config.yml'
