#!/usr/bin/env bash
# case-017-lib_text_with_password, Bash library: encrypt and decrypt a text with a password.
# The library is one file that is sourced; it defines functions and changes nothing else.
cd "$(dirname "${BASH_SOURCE[0]}")"
source ../lib/demo.sh
title "case-017-lib_text_with_password [bash, library]"
source ./prepare.sh

echo "${0}: load the library: it defines ssenc_encrypt, ssenc_decrypt, ssenc_rekey and ssenc_inspect"
run 'source "$(pwd)/../../bash/ssenc.sh"'

run 'echo "library version $SSENC_VERSION"'

echo "${0}: the password comes from SSENC_PASSWORD (or from --password-file, see case-018)"
run 'export SSENC_PASSWORD="$(cat tmp/password.txt)"'

echo "${0}: the functions read standard input and write standard output, so they fit into pipes and \$( )"
run 'encrypted="$(printf "user: admin\npassword: hunter2\n" | ssenc_encrypt)"'
run 'echo "$encrypted"'

echo "${0}: decrypt"
run 'text="$(echo "$encrypted" | ssenc_decrypt)"'
run 'echo "$text"'
check "the decrypted text equals the original" '[[ "$text" == "user: admin"$'"'"'\n'"'"'"password: hunter2" ]]'

echo "${0}: encrypting the same text again gives a different result (new random data key each time)"
run 'again="$(printf "user: admin\npassword: hunter2\n" | ssenc_encrypt)"'
check "the two encrypted texts differ" '[[ "$again" != "$encrypted" ]]'
check "both decrypt to the same text" '[[ "$(echo "$again" | ssenc_decrypt)" == "$text" ]]'

echo "${0}: the functions return the same codes as the command: 0 ok, 1 USAGE, 2 AUTH, 3 MALFORMED, 4 ENV"
run 'if echo "$encrypted" | SSENC_PASSWORD="wrong password" ssenc_decrypt > /dev/null; then echo "opened"; else echo "not opened, return code $?"; fi'

echo "${0}: sourcing the library did not change the options of this shell"
run 'set -o | grep -E "^(errexit|nounset|pipefail)"'
