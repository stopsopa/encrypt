#!/usr/bin/env bash
# Sourced by rust.sh, ts.sh and bash.sh (and it can be run on its own): starts from an empty ./tmp, makes the demo password
# and an indented file with lines of very different length.
cd "$(dirname "${BASH_SOURCE[0]}")"
declare -F run > /dev/null || source ../lib/demo.sh
rm -rf tmp && mkdir tmp

echo "${0}: prepare: a demo password and an indented file"
run 'openssl rand -base64 24 > tmp/password.txt'
cat > tmp/app.yml <<'END_OF_FILE'
app:
    name: demo
    description: a much longer line, clearly longer than all the other lines of this file

    nested:
        key: v
END_OF_FILE
run 'cat tmp/app.yml'
