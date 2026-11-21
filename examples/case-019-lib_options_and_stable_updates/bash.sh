#!/usr/bin/env bash
# case-019-lib_options_and_stable_updates, Bash library: every option of encrypt (cost, whitespace, padding, seal) and updates that change only the edited lines.
# The library is one file that is sourced; it defines functions and changes nothing else.
cd "$(dirname "${BASH_SOURCE[0]}")"
source ../lib/demo.sh
title "case-019-lib_options_and_stable_updates [bash, library]"
source ./prepare.sh

echo "${0}: load the library: it defines ssenc_encrypt, ssenc_decrypt, ssenc_rekey and ssenc_inspect"
run 'source "$(pwd)/../../bash/ssenc.sh"'

run 'export SSENC_PASSWORD="$(cat tmp/password.txt)"'

echo "${0}: --kdf sets the cost of turning the password into a key: default, strong or m=<KiB>,t=<passes>,p=<lanes>."
echo "${0}: the lower cost below is used for the rest of this demo only to keep it quick"
run 'KDF="m=19456,t=2,p=1"'
run 'ssenc_encrypt --kdf "$KDF" -i tmp/app.yml -o tmp/v1.enc'
run 'cat tmp/v1.enc'
run 'ssenc_inspect -i tmp/v1.enc'

echo "${0}: --no-preserve-ws: indentation and empty lines are encrypted too"
run 'ssenc_encrypt --kdf "$KDF" --no-preserve-ws -i tmp/app.yml | tail -n +3'

echo "${0}: --pad 0: no padding; a bigger value hides line lengths better"
run 'ssenc_encrypt --kdf "$KDF" --pad 0 -i tmp/app.yml | tail -n +3'
run 'ssenc_encrypt --kdf "$KDF" --pad 64 -i tmp/app.yml | tail -n +3'

echo "${0}: --previous: update an encrypted text; unchanged lines stay identical"
run 'sed "s/port: 8080/port: 9090/" tmp/app.yml > tmp/edited.yml'
run 'ssenc_encrypt --previous tmp/v1.enc -i tmp/edited.yml -o tmp/v2.enc'
run 'diff tmp/v1.enc tmp/v2.enc || true'
check "exactly one line changed" '[[ "$(diff tmp/v1.enc tmp/v2.enc | grep -c "^>")" == 1 ]]'

echo "${0}: writing to a file that already holds an encrypted version uses it as --previous automatically; --fresh turns that off"
run 'cp tmp/v2.enc tmp/auto.enc && ssenc_encrypt -i tmp/edited.yml -o tmp/auto.enc && cmp tmp/v2.enc tmp/auto.enc && echo "unchanged"'
run 'ssenc_encrypt --fresh --kdf "$KDF" -i tmp/edited.yml -o tmp/auto.enc; diff tmp/v2.enc tmp/auto.enc | grep -c "^>" || true'

echo "${0}: the key must open the previous version, otherwise nothing is written"
run 'SSENC_PASSWORD="another password" ssenc_encrypt --previous tmp/v1.enc -i tmp/edited.yml -o tmp/wrong.enc || echo "return code $?"'
check "no output file for the wrong key" '[[ ! -e tmp/wrong.enc ]]'

echo "${0}: --seal: a checksum over the whole file; removed or reordered lines are detected"
run 'ssenc_encrypt --kdf "$KDF" --seal -i tmp/app.yml -o tmp/sealed.enc'
run 'cat tmp/sealed.enc'
run 'sed "\$d" tmp/sealed.enc | ssenc_decrypt || echo "return code $?"'
echo "${0}: unsealed, the same removal goes unnoticed"
run 'sed "\$d" tmp/v1.enc | ssenc_decrypt'

echo "${0}: options not given are taken from the previous version: an update of a sealed file is sealed again"
run 'ssenc_encrypt -i tmp/edited.yml -o tmp/sealed.enc && ssenc_inspect -i tmp/sealed.enc'
check "still sealed" 'ssenc_inspect -i tmp/sealed.enc | grep -q "\"seal\":true"'
check "v1 decrypts to the original" 'ssenc_decrypt -i tmp/v1.enc | cmp - tmp/app.yml'
check "v2 decrypts to the edited file" 'ssenc_decrypt -i tmp/v2.enc | cmp - tmp/edited.yml'
