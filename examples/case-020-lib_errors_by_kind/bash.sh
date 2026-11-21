#!/usr/bin/env bash
# case-020-lib_errors_by_kind, Bash library: every kind of failure and how a program reacts to it.
# The library is one file that is sourced; it defines functions and changes nothing else.
cd "$(dirname "${BASH_SOURCE[0]}")"
source ../lib/demo.sh
title "case-020-lib_errors_by_kind [bash, library]"
source ./prepare.sh

echo "${0}: load the library: it defines ssenc_encrypt, ssenc_decrypt, ssenc_rekey and ssenc_inspect"
run 'source "$(pwd)/../../bash/ssenc.sh"'

run 'export SSENC_PASSWORD="$(cat tmp/password.txt)"'
run 'echo "the secret" | ssenc_encrypt --kdf m=19456,t=2,p=1 > tmp/secret.enc'

echo "${0}: the functions return 0 on success, otherwise 1 USAGE, 2 AUTH, 3 MALFORMED, 4 ENV; the message goes to standard error"

echo "${0}: AUTH (2): the key does not open the text, or the text was changed"
fails 2 'SSENC_PASSWORD="wrong" ssenc_decrypt -i tmp/secret.enc'
run 'awk "NR == 3 { c = substr(\$0, 1, 1); \$0 = (c == \"A\" ? \"B\" : \"A\") substr(\$0, 2) } { print }" tmp/secret.enc > tmp/modified.enc'
fails 2 'ssenc_decrypt -i tmp/modified.enc'

echo "${0}: MALFORMED (3): the input is not encrypted text of this format"
fails 3 'echo "just some text" | ssenc_decrypt'
fails 3 'echo "just some text" | ssenc_inspect'

echo "${0}: USAGE (1): the call itself is wrong"
fails 1 'echo x | SSENC_PASSWORD="" ssenc_encrypt'
fails 1 'echo x | ssenc_encrypt --pad 100000'
fails 1 'echo x | env -u SSENC_PASSWORD bash -c "source \"$(pwd)/../../bash/ssenc.sh\"; ssenc_encrypt"'

echo "${0}: ENV (4): something outside is missing; here an ssh key without a reachable ssh-agent"
fails 4 'echo x | ssenc_encrypt --ssh-key tmp/demo_ed25519.pub'

echo "${0}: how it looks in a real script: decide by return code, keep the message"
open_secret() {
  local code=0
  SSENC_PASSWORD="$1" ssenc_decrypt -i tmp/secret.enc 2> tmp/error.txt || code=$?
  case "$code" in
    0) ;;
    2) echo "(wrong password, ask again)" ;;
    *) echo "(cannot continue: $(cat tmp/error.txt))"; return "$code" ;;
  esac
}
run 'declare -f open_secret'
run 'open_secret "a guess"'
run 'open_secret "$(cat tmp/password.txt)"'
check "the right password gives the text" '[[ "$(open_secret "$(cat tmp/password.txt)")" == "the secret" ]]'
