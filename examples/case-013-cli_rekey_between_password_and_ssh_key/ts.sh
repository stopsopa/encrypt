#!/usr/bin/env bash
# case-013-cli_rekey_between_password_and_ssh_key, TypeScript (Node.js) command line: move a file from a password to ssh keys and back, add and remove keys.
cd "$(dirname "${BASH_SOURCE[0]}")"
source ../lib/demo.sh
SSENC="$(pwd)/../../typescript/bin/ssenc"   # runs typescript/dist/cli.ts with node
built "$SSENC" "typescript/compile.sh"
title "case-013-cli_rekey_between_password_and_ssh_key [ts, command line]"
source ./prepare.sh

echo "${0}: A private ssh-agent just for this example, with both demo keys loaded"
demo_agent_start
run 'ssh-add -q tmp/demo_ed25519 tmp/demo_rsa'

echo "${0}: The file starts out encrypted with a password"
run '"$SSENC" encrypt --password-file tmp/password.txt -i tmp/secrets.env -o tmp/secrets.env.enc'
run '"$SSENC" inspect -i tmp/secrets.env.enc'

echo "${0}: From the password to an ssh key: open with the password, write for the key"
run '"$SSENC" rekey --password-file tmp/password.txt --new-ssh-key tmp/demo_ed25519.pub -i tmp/secrets.env.enc -o tmp/secrets.env.enc'
run '"$SSENC" inspect -i tmp/secrets.env.enc'
fails 2 '"$SSENC" decrypt --password-file tmp/password.txt -i tmp/secrets.env.enc'
run '"$SSENC" decrypt --ssh-key tmp/demo_ed25519.pub -i tmp/secrets.env.enc'

echo "${0}: From one ssh key to two ssh keys plus a backup password (all new keys are listed, the old ones are gone)"
run '"$SSENC" rekey --ssh-key tmp/demo_ed25519.pub --new-ssh-key tmp/demo_ed25519.pub --new-ssh-key tmp/demo_rsa.pub --new-password-file tmp/backup-password.txt -i tmp/secrets.env.enc -o tmp/secrets.env.enc'
run '"$SSENC" inspect -i tmp/secrets.env.enc'

echo "${0}: Remove one person: rekey with everybody who stays. --rewrap-only would keep the data lines unchanged;"
echo "${0}: the default also makes a new data key, so the removed key cannot read future versions from an old copy"
run '"$SSENC" rekey --ssh-key tmp/demo_ed25519.pub --new-ssh-key tmp/demo_ed25519.pub --new-password-file tmp/backup-password.txt -i tmp/secrets.env.enc -o tmp/secrets.env.enc'
fails 2 '"$SSENC" decrypt --ssh-key tmp/demo_rsa.pub -i tmp/secrets.env.enc'

echo "${0}: And back from the ssh key to only a password"
run '"$SSENC" rekey --ssh-key tmp/demo_ed25519.pub --new-password-file tmp/password.txt -i tmp/secrets.env.enc -o tmp/secrets.env.enc'
run '"$SSENC" inspect -i tmp/secrets.env.enc'
fails 2 '"$SSENC" decrypt --ssh-key tmp/demo_ed25519.pub -i tmp/secrets.env.enc'
check "the content survived all key changes" '"$SSENC" decrypt --password-file tmp/password.txt -i tmp/secrets.env.enc | cmp - tmp/secrets.env'
