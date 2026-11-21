#!/usr/bin/env bash
# case-010-cli_rekey_change_password, Rust command line: replace the password of an encrypted file (rekey, --rewrap-only).
cd "$(dirname "${BASH_SOURCE[0]}")"
source ../lib/demo.sh
SSENC="$(pwd)/../../rust/target/release/ssenc"   # the binary built by rust/compile.sh
built "$SSENC" "rust/compile.sh"
title "case-010-cli_rekey_change_password [rust, command line]"
source ./prepare.sh

run '"$SSENC" encrypt --password-file tmp/old-password.txt -i tmp/config.yml -o tmp/config.yml.enc'
run 'cp tmp/config.yml.enc tmp/before.enc'

echo "${0}: rekey: open with the old password, write the file for the new password"
run '"$SSENC" rekey --password-file tmp/old-password.txt --new-password-file tmp/new-password.txt -i tmp/config.yml.enc -o tmp/config.yml.enc'

echo "${0}: The old password no longer opens it, the new one does"
fails 2 '"$SSENC" decrypt --password-file tmp/old-password.txt -i tmp/config.yml.enc'
run '"$SSENC" decrypt --password-file tmp/new-password.txt -i tmp/config.yml.enc'

echo "${0}: By default everything is encrypted again under a new data key: every line changed once"
run 'diff tmp/before.enc tmp/config.yml.enc | grep -c "^>" || true'

echo "${0}: The passwords can come from the environment as well: SSENC_PASSWORD (current) and SSENC_NEW_PASSWORD"
run 'SSENC_PASSWORD="$(cat tmp/new-password.txt)" SSENC_NEW_PASSWORD="third password" "$SSENC" rekey -i tmp/config.yml.enc -o tmp/config.yml.enc'
run 'SSENC_PASSWORD="third password" "$SSENC" decrypt -i tmp/config.yml.enc'

echo "${0}: --rewrap-only replaces just the key line and leaves the data lines as they are (small diff, cheap)."
echo "${0}: Weaker: someone who knows the old password and kept an old copy can still read later versions."
run 'cp tmp/config.yml.enc tmp/before-rewrap.enc'
run 'SSENC_PASSWORD="third password" "$SSENC" rekey --rewrap-only --new-password-file tmp/new-password.txt -i tmp/config.yml.enc -o tmp/config.yml.enc'
run 'diff tmp/before-rewrap.enc tmp/config.yml.enc | cut -c 1-70 || true'
check "only the key line changed" '[[ "$(diff tmp/before-rewrap.enc tmp/config.yml.enc | grep -c "^>")" == 1 ]]'
fails 2 'SSENC_PASSWORD="third password" "$SSENC" decrypt -i tmp/config.yml.enc'

echo "${0}: rekey can set the cost of the new password too"
run '"$SSENC" rekey --kdf m=19456,t=2,p=1 --password-file tmp/new-password.txt --new-password-file tmp/new-password.txt -i tmp/config.yml.enc -o tmp/config.yml.enc'
run '"$SSENC" inspect -i tmp/config.yml.enc'
check "the content survived all key changes" '"$SSENC" decrypt --password-file tmp/new-password.txt -i tmp/config.yml.enc | cmp - tmp/config.yml'
