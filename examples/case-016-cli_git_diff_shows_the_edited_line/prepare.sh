#!/usr/bin/env bash
# Sourced by rust.sh, ts.sh and bash.sh (and it can be run on its own): starts from an empty ./tmp, generates a demo password
# and a new git repository with one plain settings file.
cd "$(dirname "${BASH_SOURCE[0]}")"
declare -F run > /dev/null || source ../lib/demo.sh
rm -rf tmp && mkdir tmp

echo "${0}: prepare: a demo password"
run 'openssl rand -base64 24 > tmp/password.txt'

echo "${0}: prepare: a new git repository in tmp/repo; the plain file is ignored, only the encrypted one is committed"
run 'git init -q -b main tmp/repo'
run 'git -C tmp/repo config user.name "Demo User" && git -C tmp/repo config user.email "demo@example.invalid" && git -C tmp/repo config commit.gpgsign false'
run 'printf "host: db.internal\nport: 5432\nuser: admin\npassword: hunter2\ntimeout: 30\n" > tmp/repo/settings.yml'
run 'echo "settings.yml" > tmp/repo/.gitignore'
