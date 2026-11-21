#!/usr/bin/env bash
# case-004-cli_inspect_without_key, Rust command line: look at an encrypted file without a key (mode, parameters, key slots).
cd "$(dirname "${BASH_SOURCE[0]}")"
source ../lib/demo.sh
SSENC="$(pwd)/../../rust/target/release/ssenc"   # the binary built by rust/compile.sh
built "$SSENC" "rust/compile.sh"
title "case-004-cli_inspect_without_key [rust, command line]"
source ./prepare.sh

echo "${0}: Two encrypted files: one in lines mode, one in blob mode"
run '"$SSENC" encrypt --password-file tmp/password.txt -i tmp/notes.txt -o tmp/notes.txt.enc'
run '"$SSENC" encrypt --mode blob --password-file tmp/password.txt -i tmp/data.bin -o tmp/data.bin.enc'

echo "${0}: inspect needs no key: it prints how a file was encrypted and which keys open it, as JSON"
run '"$SSENC" inspect -i tmp/notes.txt.enc'
run '"$SSENC" inspect -i tmp/data.bin.enc'

echo "${0}: It reads standard input too"
run '"$SSENC" inspect < tmp/notes.txt.enc'

echo "${0}: Use it in a script, e.g. to tell encrypted files from plain ones"
run 'for f in tmp/notes.txt tmp/notes.txt.enc; do
  if "$SSENC" inspect -i "$f" > /dev/null 2>&1; then echo "$f: encrypted"; else echo "$f: not encrypted"; fi
done'

echo "${0}: Which implementation and version is this?"
run '"$SSENC" --version'

check "inspect reports lines mode" '"$SSENC" inspect -i tmp/notes.txt.enc | grep -q "\"mode\":\"lines\""'
check "inspect reports blob mode" '"$SSENC" inspect -i tmp/data.bin.enc | grep -q "\"mode\":\"blob\""'
