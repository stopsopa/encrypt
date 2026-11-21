#!/usr/bin/env bash
# Sourced by rust.sh, ts.sh and bash.sh (and it can be run on its own): starts from an empty
# ./tmp, generates a random key file, a demo password and 60 small files to encrypt.
cd "$(dirname "${BASH_SOURCE[0]}")"
declare -F run > /dev/null || source ../lib/demo.sh
rm -rf tmp && mkdir -p tmp/plain tmp/fast tmp/decrypted

echo "${0}: prepare: a random 256-bit key in a file (keep such a file like a private key), a demo password and 60 files"
run 'openssl rand -base64 32 > tmp/bulk.key'
run 'openssl rand -base64 24 > tmp/password.txt'
run 'for i in $(seq -w 1 60); do printf "id: %s\nvalue: %s\nnote: file number %s\n" "$i" "$RANDOM" "$i" > "tmp/plain/file-$i.txt"; done'
run 'ls tmp/plain | wc -l'
