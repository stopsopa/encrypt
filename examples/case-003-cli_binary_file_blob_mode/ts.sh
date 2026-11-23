#!/usr/bin/env bash
# case-003-cli_binary_file_blob_mode, TypeScript (Node.js) command line: encrypt a binary file into an ASCII text file (blob mode) and decrypt it.
cd "$(dirname "${BASH_SOURCE[0]}")"
source ../lib/demo.sh
SSENC="$(pwd)/../../typescript/bin/ssenc"   # runs typescript/dist/cli.ts with node
built "$SSENC" "typescript/compile.sh"
title "case-003-cli_binary_file_blob_mode [ts, command line]"
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

echo "${0}: --mode auto decides by itself: lines for text (no NUL byte, valid UTF-8), blob for anything else"
run '"$SSENC" encrypt --mode auto --password-file tmp/password.txt -i tmp/photo.bin -o tmp/photo.auto.enc'
run '"$SSENC" encrypt --mode auto --password-file tmp/password.txt -i tmp/notes.txt -o tmp/notes.auto.enc'
run 'head -n 1 tmp/photo.auto.enc tmp/notes.auto.enc'
check "the binary file became a blob" 'head -n 1 tmp/photo.auto.enc | grep -q "^#ssenc1 blob "'
check "the text file was encrypted line by line" 'head -n 1 tmp/notes.auto.enc | grep -q "^#ssenc1 lines "'

echo "${0}: An existing file keeps its mode: put a bad byte into the text and encrypt again to the same file"
run 'cp tmp/notes.auto.enc tmp/notes.before.enc'
run 'printf "line one\nline \377 two\nline three\n" > tmp/notes.txt'
run '"$SSENC" encrypt --mode auto --password-file tmp/password.txt -i tmp/notes.txt -o tmp/notes.auto.enc'
run 'diff tmp/notes.before.enc tmp/notes.auto.enc || true'
check "still lines mode, and only the edited line changed" '[ "$(diff tmp/notes.before.enc tmp/notes.auto.enc | grep -c "^>")" = 1 ] && head -n 1 tmp/notes.auto.enc | grep -q "^#ssenc1 lines "'
check "it decrypts to the edited file" '"$SSENC" decrypt --password-file tmp/password.txt -i tmp/notes.auto.enc | cmp - tmp/notes.txt'

echo "${0}: --fresh forgets the existing file, so the mode is detected again: now it is a blob"
run '"$SSENC" encrypt --mode auto --fresh --password-file tmp/password.txt -i tmp/notes.txt -o tmp/notes.auto.enc'
run 'head -n 1 tmp/notes.auto.enc'
check "detected again as binary" 'head -n 1 tmp/notes.auto.enc | grep -q "^#ssenc1 blob "'
