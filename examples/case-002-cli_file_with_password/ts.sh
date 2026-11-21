#!/usr/bin/env bash
# case-002-cli_file_with_password, TypeScript (Node.js) command line: encrypt a text file with a password file and decrypt it again.
cd "$(dirname "${BASH_SOURCE[0]}")"
source ../lib/demo.sh
SSENC="$(pwd)/../../typescript/bin/ssenc"   # runs typescript/dist/cli.ts with node
built "$SSENC" "typescript/compile.sh"
title "case-002-cli_file_with_password [ts, command line]"
source ./prepare.sh

echo "${0}: Encrypt a file: -i input, -o output, password read from a file"
run '"$SSENC" encrypt --password-file tmp/password.txt -i tmp/config.yml -o tmp/config.yml.enc'

echo "${0}: The result is a text file with the same number of lines; indentation and blank lines stay visible"
run 'cat tmp/config.yml.enc'

echo "${0}: Decrypt it to a new file and compare with the original"
run '"$SSENC" decrypt --password-file tmp/password.txt -i tmp/config.yml.enc -o tmp/config.decrypted.yml'
run 'cmp tmp/config.yml tmp/config.decrypted.yml && echo "identical"'

echo "${0}: Decrypt to the terminal instead (no -o)"
run '"$SSENC" decrypt --password-file tmp/password.txt -i tmp/config.yml.enc'

echo "${0}: Input and output may be the same file: encrypt in place, then decrypt in place"
run 'cp tmp/config.yml tmp/inplace.yml'
run '"$SSENC" encrypt --password-file tmp/password.txt -i tmp/inplace.yml -o tmp/inplace.yml'
run 'head -n 3 tmp/inplace.yml'
run '"$SSENC" decrypt --password-file tmp/password.txt -i tmp/inplace.yml -o tmp/inplace.yml'
check "the file is back to the original" 'cmp tmp/config.yml tmp/inplace.yml'
