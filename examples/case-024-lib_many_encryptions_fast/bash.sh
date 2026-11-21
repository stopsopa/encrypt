#!/usr/bin/env bash
# case-024-lib_many_encryptions_fast, Bash library: encrypt, decrypt and update many files quickly from a program.
# The library is one file that is sourced; it defines functions and changes nothing else.
cd "$(dirname "${BASH_SOURCE[0]}")"
source ../lib/demo.sh
title "case-024-lib_many_encryptions_fast [bash, library]"
source ./prepare.sh

echo "${0}: load the library: it defines ssenc_encrypt, ssenc_decrypt, ssenc_rekey and ssenc_inspect"
run 'source "$(pwd)/../../bash/ssenc.sh"'

echo "${0}: each operation with a password runs Argon2id once, on purpose slow. At the default cost, 3 files:"
timed 'for f in tmp/plain/file-0[1-3].txt; do
  ssenc_encrypt --password-file tmp/password.txt -i "$f" > /dev/null
done'

echo "${0}: that cost protects passwords a person could guess; a random 256-bit key needs none of it."
echo "${0}: a random key and the minimum cost (--kdf m=8,t=1,p=1), all 60 files:"
timed 'for f in tmp/plain/*.txt; do
  ssenc_encrypt --kdf m=8,t=1,p=1 --password-file tmp/bulk.key -i "$f" -o "tmp/fast/$(basename "$f").enc"
done'

echo "${0}: decrypting needs no option: the cost is stored in every file"
timed 'for f in tmp/fast/*.enc; do
  ssenc_decrypt --password-file tmp/bulk.key -i "$f" -o "tmp/decrypted/$(basename "$f" .enc)"
done'
run 'diff -r tmp/plain tmp/decrypted && echo "all 60 files identical to the originals"'

echo "${0}: updating all of them is just as fast: writing to the existing encrypted file changes only the new line"
timed 'for f in tmp/plain/*.txt; do
  { cat "$f"; echo "added: yes"; } | ssenc_encrypt --password-file tmp/bulk.key -o "tmp/fast/$(basename "$f").enc"
done'
check "the updated file decrypts to the longer text" '[[ "$(ssenc_decrypt --password-file tmp/bulk.key -i tmp/fast/file-33.txt.enc | tail -n 1)" == "added: yes" ]]'

echo "${0}: the files are independent: run the functions in the background, here 6 at a time"
timed 'n=0
for f in tmp/plain/*.txt; do
  ssenc_encrypt --kdf m=8,t=1,p=1 --password-file tmp/bulk.key -i "$f" > /dev/null &
  n=$((n + 1))
  if ((n % 6 == 0)); then wait; fi
done
wait'

echo "${0}: what is left per file in Bash is the start of several openssl processes; for thousands of files use the Rust library or command."
echo "${0}: NEVER use the minimum cost with a password a person chose: guessing it would be cheap."
