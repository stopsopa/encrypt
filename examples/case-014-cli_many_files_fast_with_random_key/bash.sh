#!/usr/bin/env bash
# case-014-cli_many_files_fast_with_random_key, Bash command line: encrypt many files quickly: a random key file and the minimum password cost.
cd "$(dirname "${BASH_SOURCE[0]}")"
source ../lib/demo.sh
SSENC="$(pwd)/../../bash/bin/ssenc"   # bash + openssl, nothing to build
built "$SSENC" "(it is part of the repository)"
title "case-014-cli_many_files_fast_with_random_key [bash, command line]"
source ./prepare.sh

echo "${0}: Every password operation pays the deliberate Argon2id cost once. At the default cost, 5 files:"
timed 'for f in tmp/plain/file-0[1-5].txt; do
  "$SSENC" encrypt --password-file tmp/bulk.key -i "$f" -o "tmp/slow/$(basename "$f").enc"
done'

echo "${0}: That cost only protects passwords a person could guess. The key here is 256 random bits,"
echo "${0}: so the cost can go down to the minimum without losing anything: --kdf m=8,t=1,p=1. All 30 files:"
timed 'for f in tmp/plain/*.txt; do
  "$SSENC" encrypt --kdf m=8,t=1,p=1 --password-file tmp/bulk.key -i "$f" -o "tmp/fast/$(basename "$f").enc"
done'
run 'head -n 2 tmp/fast/file-01.txt.enc | cut -c 1-60'

echo "${0}: Decrypting needs no option: the cost is read from each file"
timed 'for f in tmp/fast/*.enc; do
  "$SSENC" decrypt --password-file tmp/bulk.key -i "$f" -o "tmp/decrypted/$(basename "$f" .enc)"
done'
run 'diff -r tmp/plain tmp/decrypted && echo "all 30 files identical"'

echo "${0}: The files are independent, so they can be done in parallel (here 4 at a time)"
timed 'ls tmp/plain | xargs -P 4 -I {} "$SSENC" encrypt --kdf m=8,t=1,p=1 --password-file tmp/bulk.key -i tmp/plain/{} -o tmp/parallel/{}.enc'
check "30 files were written in parallel" '[[ "$(ls tmp/parallel | wc -l | tr -d " ")" == 30 ]]'
check "a file from the parallel run decrypts correctly" '"$SSENC" decrypt --password-file tmp/bulk.key -i tmp/parallel/file-17.txt.enc | cmp - tmp/plain/file-17.txt'

echo "${0}: NEVER use the minimum cost with a password a person chose: guessing it would be cheap."
echo "${0}: An ssh key (see case-011) is the other way to avoid the cost: it does not use Argon2id at all."
