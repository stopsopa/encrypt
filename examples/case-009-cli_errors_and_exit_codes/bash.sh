#!/usr/bin/env bash
# case-009-cli_errors_and_exit_codes, Bash command line: every kind of failure, its exit code and its message.
cd "$(dirname "${BASH_SOURCE[0]}")"
source ../lib/demo.sh
SSENC="$(pwd)/../../bash/bin/ssenc"   # bash + openssl, nothing to build
built "$SSENC" "(it is part of the repository)"
title "case-009-cli_errors_and_exit_codes [bash, command line]"
source ./prepare.sh

run '"$SSENC" encrypt --password-file tmp/password.txt -i tmp/secret.txt -o tmp/secret.enc'

echo "${0}: Exit code 0: success"
run '"$SSENC" decrypt --password-file tmp/password.txt -i tmp/secret.enc; echo "    exit code $?"'

echo "${0}: Exit code 2 (AUTH): wrong password. The message goes to standard error, nothing is written to the output"
fails 2 'SSENC_PASSWORD="wrong password" "$SSENC" decrypt -i tmp/secret.enc -o tmp/out.txt'
check "the output file was not created" '[[ ! -e tmp/out.txt ]]'

echo "${0}: Exit code 2 (AUTH): the encrypted file was modified"
run 'awk "NR == 3 { c = substr(\$0, 1, 1); \$0 = (c == \"A\" ? \"B\" : \"A\") substr(\$0, 2) } { print }" tmp/secret.enc > tmp/modified.enc'
fails 2 '"$SSENC" decrypt --password-file tmp/password.txt -i tmp/modified.enc'

echo "${0}: Exit code 3 (MALFORMED): the input is not an encrypted file"
fails 3 'echo "just some text" | "$SSENC" decrypt --password-file tmp/password.txt'
fails 3 '"$SSENC" inspect -i tmp/secret.txt'

echo "${0}: Exit code 1 (USAGE): no key given, empty password, unknown option"
fails 1 '"$SSENC" decrypt -i tmp/secret.enc < /dev/null'
fails 1 'SSENC_PASSWORD="" "$SSENC" encrypt -i tmp/secret.txt -o tmp/out.enc'
fails 1 '"$SSENC" decrypt --no-such-option -i tmp/secret.enc'

echo "${0}: Exit code 4 (ENV): an ssh key is asked for, but no ssh-agent is reachable"
fails 4 '"$SSENC" encrypt --ssh-key tmp/demo_ed25519.pub -i tmp/secret.txt -o tmp/out.enc'

echo "${0}: In a script: branch on the exit code"
run 'code=0
SSENC_PASSWORD="wrong password" "$SSENC" decrypt -i tmp/secret.enc > tmp/plain.txt 2> tmp/error.txt || code=$?
case "$code" in
  0) echo "decrypted" ;;
  2) echo "wrong password or modified file: $(cat tmp/error.txt)" ;;
  3) echo "not an encrypted file" ;;
  *) echo "other problem ($code): $(cat tmp/error.txt)" ;;
esac'
