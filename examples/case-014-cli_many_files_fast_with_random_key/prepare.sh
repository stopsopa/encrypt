#!/usr/bin/env bash
# Sourced by rust.sh, ts.sh and bash.sh (and it can be run on its own): starts from an empty ./tmp, generates a random key
# file and 30 small files to encrypt.
cd "$(dirname "${BASH_SOURCE[0]}")"
declare -F run > /dev/null || source ../lib/demo.sh
rm -rf tmp && mkdir -p tmp/plain tmp/slow tmp/fast tmp/parallel tmp/decrypted

echo "${0}: prepare: a random 256-bit key in a file (keep such a file like a private key) and 30 files"
run 'openssl rand -base64 32 > tmp/bulk.key'
run 'for i in $(seq -w 1 30); do printf "id: %s\nvalue: %s\nnote: file number %s\n" "$i" "$RANDOM" "$i" > "tmp/plain/file-$i.txt"; done'
run 'ls tmp/plain | wc -l'
