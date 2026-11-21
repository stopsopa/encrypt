#!/usr/bin/env bash
# case-005-cli_update_changes_only_edited_lines, Bash command line: re-encrypt an edited file so that only the edited lines change (stable diffs).
cd "$(dirname "${BASH_SOURCE[0]}")"
source ../lib/demo.sh
SSENC="$(pwd)/../../bash/bin/ssenc"   # bash + openssl, nothing to build
built "$SSENC" "(it is part of the repository)"
title "case-005-cli_update_changes_only_edited_lines [bash, command line]"
source ./prepare.sh

echo "${0}: First version"
run '"$SSENC" encrypt --password-file tmp/password.txt -i tmp/config.yml -o tmp/config.yml.enc'
run 'cp tmp/config.yml.enc tmp/version1.enc'

echo "${0}: Change one line of the plain file ..."
run 'sed "s/port: 5432/port: 6543/" tmp/config.yml > tmp/config.new && mv tmp/config.new tmp/config.yml'

echo "${0}: ... and encrypt again to the SAME output file: the existing file is reused, so only the changed line differs"
run '"$SSENC" encrypt --password-file tmp/password.txt -i tmp/config.yml -o tmp/config.yml.enc'
run 'diff tmp/version1.enc tmp/config.yml.enc || true'
check "exactly one line of the encrypted file changed" '[[ "$(diff tmp/version1.enc tmp/config.yml.enc | grep -c "^>")" == 1 ]]'

echo "${0}: Writing somewhere else? Name the earlier encrypted version with --previous"
run '"$SSENC" encrypt --password-file tmp/password.txt --previous tmp/version1.enc -i tmp/config.yml -o tmp/elsewhere.enc'
run 'cmp tmp/config.yml.enc tmp/elsewhere.enc && echo "identical to the file made above"'

echo "${0}: --fresh ignores the existing output: new data key, every line changes (this is also what happens without a previous file)"
run 'cp tmp/config.yml.enc tmp/version2.enc'
run '"$SSENC" encrypt --fresh --password-file tmp/password.txt -i tmp/config.yml -o tmp/config.yml.enc'
run 'diff tmp/version2.enc tmp/config.yml.enc | grep -c "^>" || true'
check "all 6 data lines and the key line changed" '[[ "$(diff tmp/version2.enc tmp/config.yml.enc | grep -c "^>")" == 7 ]]'

echo "${0}: Reusing needs the right key: with a wrong password nothing is written"
fails 2 'SSENC_PASSWORD="not the password" "$SSENC" encrypt -i tmp/config.yml -o tmp/config.yml.enc'
check "the file still decrypts to the current plain text" '"$SSENC" decrypt --password-file tmp/password.txt -i tmp/config.yml.enc | cmp - tmp/config.yml'
