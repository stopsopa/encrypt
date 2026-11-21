#!/usr/bin/env bash
# case-021-lib_rekey_replace_keys, Bash library: replace the keys of an encrypted text, with or without a new data key.
# The library is one file that is sourced; it defines functions and changes nothing else.
cd "$(dirname "${BASH_SOURCE[0]}")"
source ../lib/demo.sh
title "case-021-lib_rekey_replace_keys [bash, library]"
source ./prepare.sh

echo "${0}: load the library: it defines ssenc_encrypt, ssenc_decrypt, ssenc_rekey and ssenc_inspect"
run 'source "$(pwd)/../../bash/ssenc.sh"'

run 'KDF="m=19456,t=2,p=1"   # lower cost, only to keep the demo quick'
run 'printf "host: db.internal\nuser: admin\npassword: hunter2\n" > tmp/plain.txt'
run 'ssenc_encrypt --kdf "$KDF" --password-file tmp/old-password.txt -i tmp/plain.txt -o tmp/original.enc'
run 'cat tmp/original.enc'

echo "${0}: ssenc_rekey: open with the old key, write for the new one; everything is encrypted again under a new data key"
run 'ssenc_rekey --kdf "$KDF" --password-file tmp/old-password.txt --new-password-file tmp/new-password.txt -i tmp/original.enc -o tmp/rotated.enc'
run 'cat tmp/rotated.enc'
fails 2 'ssenc_decrypt --password-file tmp/old-password.txt -i tmp/rotated.enc'
run 'ssenc_decrypt --password-file tmp/new-password.txt -i tmp/rotated.enc'
check "every line changed" '[[ "$(diff tmp/original.enc tmp/rotated.enc | grep -c "^>")" == 4 ]]'

echo "${0}: --rewrap-only: only the key line is replaced, the data lines stay."
echo "${0}: cheap and a small diff, but weaker: whoever knows the old password and kept an old copy can still read later versions"
run 'ssenc_rekey --rewrap-only --kdf "$KDF" --password-file tmp/old-password.txt --new-password-file tmp/new-password.txt -i tmp/original.enc -o tmp/rewrapped.enc'
run 'diff tmp/original.enc tmp/rewrapped.enc | cut -c 1-70 || true'
check "only the key line changed" '[[ "$(diff tmp/original.enc tmp/rewrapped.enc | grep -c "^>")" == 1 ]]'
fails 2 'ssenc_decrypt --password-file tmp/old-password.txt -i tmp/rewrapped.enc'

echo "${0}: the passwords can come from the environment instead: SSENC_PASSWORD (current) and SSENC_NEW_PASSWORD"
run 'SSENC_PASSWORD="$(cat tmp/new-password.txt)" SSENC_NEW_PASSWORD="a third password" ssenc_rekey --kdf "$KDF" < tmp/rotated.enc > tmp/third.enc'
run 'SSENC_PASSWORD="a third password" ssenc_decrypt -i tmp/third.enc'

echo "${0}: without --kdf the new password gets the default cost"
run 'SSENC_PASSWORD="a third password" ssenc_rekey --new-password-file tmp/new-password.txt -i tmp/third.enc | ssenc_inspect'

echo "${0}: the mode and its settings are kept: a blob stays a blob with its chunk size"
run 'head -c 3000 /dev/urandom > tmp/data.bin'
run 'ssenc_encrypt --mode blob --chunk 1024 --kdf "$KDF" --password-file tmp/old-password.txt -i tmp/data.bin -o tmp/data.enc'
run 'ssenc_rekey --kdf "$KDF" --password-file tmp/old-password.txt --new-password-file tmp/new-password.txt -i tmp/data.enc -o tmp/data.enc'
run 'ssenc_inspect -i tmp/data.enc'
check "the rekeyed blob decrypts to the original" 'ssenc_decrypt --password-file tmp/new-password.txt -i tmp/data.enc | cmp - tmp/data.bin'
