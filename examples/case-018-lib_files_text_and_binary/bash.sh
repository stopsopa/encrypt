#!/usr/bin/env bash
# case-018-lib_files_text_and_binary, Bash library: encrypt a text file line by line and a binary file as a blob, inspect and decrypt them.
# The library is one file that is sourced; it defines functions and changes nothing else.
cd "$(dirname "${BASH_SOURCE[0]}")"
source ../lib/demo.sh
title "case-018-lib_files_text_and_binary [bash, library]"
source ./prepare.sh

echo "${0}: load the library: it defines ssenc_encrypt, ssenc_decrypt, ssenc_rekey and ssenc_inspect"
run 'source "$(pwd)/../../bash/ssenc.sh"'

echo "${0}: a text file, line by line: -i and -o name files, --password-file names the password"
run 'ssenc_encrypt --password-file tmp/password.txt -i tmp/config.yml -o tmp/config.yml.enc'
run 'cat tmp/config.yml.enc'

echo "${0}: a binary file as a blob"
run 'ssenc_encrypt --mode blob --password-file tmp/password.txt -i tmp/photo.bin -o tmp/photo.bin.enc'
run 'head -n 4 tmp/photo.bin.enc'
run 'wc -c tmp/photo.bin tmp/photo.bin.enc'

echo "${0}: ssenc_inspect needs no key"
run 'ssenc_inspect -i tmp/config.yml.enc'
run 'ssenc_inspect < tmp/photo.bin.enc'

echo "${0}: decrypt; mode and settings are read from the encrypted file"
run 'ssenc_decrypt --password-file tmp/password.txt -i tmp/config.yml.enc'
run 'ssenc_decrypt --password-file tmp/password.txt -i tmp/photo.bin.enc -o tmp/photo.decrypted.bin'
run 'cmp tmp/photo.bin tmp/photo.decrypted.bin && echo "identical"'

echo "${0}: binary data must go through files or pipes, never through a shell variable (variables cannot hold NUL bytes)"
run 'ssenc_decrypt --password-file tmp/password.txt < tmp/photo.bin.enc | cmp - tmp/photo.bin && echo "identical through a pipe"'

echo "${0}: blob mode with a smaller chunk size"
run 'ssenc_encrypt --mode blob --chunk 4096 --password-file tmp/password.txt -i tmp/photo.bin -o tmp/small.enc'
run 'ssenc_inspect -i tmp/small.enc'
check "the file with small chunks decrypts to the original" 'ssenc_decrypt --password-file tmp/password.txt -i tmp/small.enc | cmp - tmp/photo.bin'
