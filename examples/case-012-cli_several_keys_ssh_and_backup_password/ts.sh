#!/usr/bin/env bash
# case-012-cli_several_keys_ssh_and_backup_password, TypeScript (Node.js) command line: one file that several ssh keys and a backup password can open.
cd "$(dirname "${BASH_SOURCE[0]}")"
source ../lib/demo.sh
SSENC="$(pwd)/../../typescript/bin/ssenc"   # runs typescript/dist/cli.ts with node
built "$SSENC" "typescript/compile.sh"
title "case-012-cli_several_keys_ssh_and_backup_password [ts, command line]"
source ./prepare.sh

echo "${0}: A private ssh-agent just for this example, with all three keys loaded"
demo_agent_start
run 'ssh-add -q tmp/alice_ed25519 tmp/bob_rsa tmp/carol_ecdsa'

echo "${0}: One file, three ways in: the ssh keys of alice and bob, and a backup password"
run '"$SSENC" encrypt --ssh-key tmp/alice_ed25519.pub --ssh-key tmp/bob_rsa.pub --password-file tmp/backup-password.txt -i tmp/secrets.env -o tmp/secrets.env.enc'
run 'cut -c 1-100 tmp/secrets.env.enc'
run '"$SSENC" inspect -i tmp/secrets.env.enc'

echo "${0}: Any ONE of them opens it"
run '"$SSENC" decrypt --ssh-key tmp/alice_ed25519.pub -i tmp/secrets.env.enc'
run '"$SSENC" decrypt --ssh-key tmp/bob_rsa.pub -i tmp/secrets.env.enc'
run '"$SSENC" decrypt --password-file tmp/backup-password.txt -i tmp/secrets.env.enc'

echo "${0}: The ssh key is lost (here: removed from the agent)? The backup password still works"
run 'ssh-add -q -d tmp/alice_ed25519'
fails 4 '"$SSENC" decrypt --ssh-key tmp/alice_ed25519.pub -i tmp/secrets.env.enc'
run '"$SSENC" decrypt --password-file tmp/backup-password.txt -i tmp/secrets.env.enc'

echo "${0}: Updating the file with one key keeps all three ways in (bob edits, using only his key)"
run 'echo "REGION=eu-west-1" >> tmp/secrets.env'
run '"$SSENC" encrypt --ssh-key tmp/bob_rsa.pub -i tmp/secrets.env -o tmp/secrets.env.enc'
run '"$SSENC" inspect -i tmp/secrets.env.enc'
check "the updated file still has three key slots" '[[ "$(grep -c "^#slot" tmp/secrets.env.enc)" == 3 ]]'
check "and the password opens the updated content" '"$SSENC" decrypt --password-file tmp/backup-password.txt -i tmp/secrets.env.enc | cmp - tmp/secrets.env'

echo "${0}: ECDSA (and hardware sk-) keys are refused: their signatures differ every time, so the key could not be derived again"
fails 4 '"$SSENC" encrypt --ssh-key tmp/carol_ecdsa.pub -i tmp/secrets.env -o tmp/carol.enc'
check "nothing was written for the refused key" '[[ ! -e tmp/carol.enc ]]'
