#!/usr/bin/env bash
# case-003-cli_binary_file_blob_mode, Rust command line: encrypt a binary file into an ASCII text file (blob mode) and decrypt it.
cd "$(dirname "${BASH_SOURCE[0]}")"
source ../lib/demo.sh
SSENC="$(pwd)/../../rust/target/release/ssenc"   # the binary built by rust/compile.sh
built "$SSENC" "rust/compile.sh"
title "case-003-cli_binary_file_blob_mode [rust, command line]"
source ./prepare.sh

echo "${0}: Blob mode encrypts any bytes as a whole: --mode blob"
run '"$SSENC" encrypt --mode blob --password-file tmp/password.txt -i tmp/photo.bin -o tmp/photo.bin.enc'

echo "${0}: The result is ASCII text, 76 characters per line (two header lines, then the data)"
run 'head -n 4 tmp/photo.bin.enc'
run 'wc -c tmp/photo.bin tmp/photo.bin.enc'

echo "${0}: Decrypt and compare byte by byte"
run '"$SSENC" decrypt --password-file tmp/password.txt -i tmp/photo.bin.enc -o tmp/photo.decrypted.bin'
run 'cmp tmp/photo.bin tmp/photo.decrypted.bin && echo "identical"'

echo "${0}: Blob mode is also for text whose line structure must not show"
run '"$SSENC" encrypt --mode blob --password-file tmp/password.txt -i tmp/notes.txt -o tmp/notes.txt.enc'
run 'cat tmp/notes.txt.enc'
run '"$SSENC" decrypt --password-file tmp/password.txt -i tmp/notes.txt.enc'

echo "${0}: --chunk N sets the size of the separately authenticated pieces (default 65536 bytes)"
run '"$SSENC" encrypt --mode blob --chunk 16384 --password-file tmp/password.txt -i tmp/photo.bin -o tmp/photo.chunk.enc'
run 'head -n 1 tmp/photo.chunk.enc'
run '"$SSENC" decrypt --password-file tmp/password.txt -i tmp/photo.chunk.enc -o tmp/photo.chunk.bin'
check "the file encrypted with another chunk size decrypts to the original" 'cmp tmp/photo.bin tmp/photo.chunk.bin'
