#!/usr/bin/env bash
# case-007-cli_seal_detects_removed_lines, TypeScript (Node.js) command line: what tampering is detected by default and what --seal adds.
cd "$(dirname "${BASH_SOURCE[0]}")"
source ../lib/demo.sh
SSENC="$(pwd)/../../typescript/bin/ssenc"   # runs typescript/dist/cli.ts with node
built "$SSENC" "typescript/compile.sh"
title "case-007-cli_seal_detects_removed_lines [ts, command line]"
source ./prepare.sh

echo "${0}: Every line is authenticated: change one character of an encrypted line and decryption refuses"
run '"$SSENC" encrypt --password-file tmp/password.txt -i tmp/rules.txt -o tmp/rules.enc'
run 'awk "NR == 4 { c = substr(\$0, 1, 1); \$0 = (c == \"A\" ? \"B\" : \"A\") substr(\$0, 2) } { print }" tmp/rules.enc > tmp/modified.enc'
run 'diff tmp/rules.enc tmp/modified.enc || true'
fails 2 '"$SSENC" decrypt --password-file tmp/password.txt -i tmp/modified.enc'

echo "${0}: But lines are independent, so a REMOVED line goes unnoticed: here the 'deny' line is deleted"
run 'sed "5d" tmp/rules.enc > tmp/shortened.enc'
run '"$SSENC" decrypt --password-file tmp/password.txt -i tmp/shortened.enc'

echo "${0}: --seal adds a checksum over the whole file ..."
run '"$SSENC" encrypt --seal --password-file tmp/password.txt -i tmp/rules.txt -o tmp/sealed.enc'
run 'cat tmp/sealed.enc'
run '"$SSENC" decrypt --password-file tmp/password.txt -i tmp/sealed.enc'

echo "${0}: ... now removing a line, or swapping two lines, is detected"
run 'sed "6d" tmp/sealed.enc > tmp/sealed-shortened.enc'
fails 2 '"$SSENC" decrypt --password-file tmp/password.txt -i tmp/sealed-shortened.enc'
run 'awk "NR == 4 { held = \$0; next } NR == 5 { print; print held; next } { print }" tmp/sealed.enc > tmp/sealed-swapped.enc'
fails 2 '"$SSENC" decrypt --password-file tmp/password.txt -i tmp/sealed-swapped.enc'

echo "${0}: A sealed file stays sealed when it is updated (the setting is taken from the existing file)"
run 'echo "allow: dave" >> tmp/rules.txt'
run '"$SSENC" encrypt --password-file tmp/password.txt -i tmp/rules.txt -o tmp/sealed.enc'
run '"$SSENC" inspect -i tmp/sealed.enc'
check "the updated file is still sealed" '"$SSENC" inspect -i tmp/sealed.enc | grep -q "\"seal\":true"'
check "and decrypts to the new content" '"$SSENC" decrypt --password-file tmp/password.txt -i tmp/sealed.enc | cmp - tmp/rules.txt'
