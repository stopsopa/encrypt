#!/usr/bin/env bash
# case-011-cli_ssh_key_from_ssh_agent, TypeScript (Node.js) command line: encrypt and decrypt with an ssh key held by ssh-agent instead of a password.
cd "$(dirname "${BASH_SOURCE[0]}")"
source ../lib/demo.sh
SSENC="$(pwd)/../../typescript/bin/ssenc"   # runs typescript/dist/cli.ts with node
built "$SSENC" "typescript/compile.sh"
title "case-011-cli_ssh_key_from_ssh_agent [ts, command line]"
source ./prepare.sh

echo "${0}: A private ssh-agent just for this example (your own agent is never used), with the demo key loaded"
demo_agent_start
run 'ssh-add -q tmp/demo_ed25519'
run 'ssh-add -l'

echo "${0}: Encrypt for the ssh key: name the PUBLIC key file. No password is involved"
run '"$SSENC" encrypt --ssh-key tmp/demo_ed25519.pub -i tmp/secrets.env -o tmp/secrets.env.enc'
run 'cat tmp/secrets.env.enc'

echo "${0}: Decrypt: the agent makes a signature with the private key, the key is derived from that signature"
run '"$SSENC" decrypt --ssh-key tmp/demo_ed25519.pub -i tmp/secrets.env.enc'

echo "${0}: The key can also be named by its fingerprint, as printed by ssh-add -l"
run 'FINGERPRINT="$(ssh-keygen -lf tmp/demo_ed25519.pub | awk "{ print \$2 }")"; echo "$FINGERPRINT"'
run '"$SSENC" decrypt --ssh-key "$FINGERPRINT" -i tmp/secrets.env.enc'

echo "${0}: inspect shows which ssh key opens the file"
run '"$SSENC" inspect -i tmp/secrets.env.enc'

echo "${0}: Updating works as with a password: only the edited line changes"
run 'cp tmp/secrets.env.enc tmp/before.enc'
run 'sed "s/REGION=eu-west-1/REGION=us-east-1/" tmp/secrets.env > tmp/new.env && mv tmp/new.env tmp/secrets.env'
run '"$SSENC" encrypt --ssh-key tmp/demo_ed25519.pub -i tmp/secrets.env -o tmp/secrets.env.enc'
run 'diff tmp/before.enc tmp/secrets.env.enc || true'
check "exactly one line changed" '[[ "$(diff tmp/before.enc tmp/secrets.env.enc | grep -c "^>")" == 1 ]]'

echo "${0}: An RSA key works the same way"
run 'ssh-add -q tmp/demo_rsa'
run '"$SSENC" encrypt --mode blob --ssh-key tmp/demo_rsa.pub -i tmp/secrets.env -o tmp/rsa.enc'
run '"$SSENC" inspect -i tmp/rsa.enc'
check "the RSA-encrypted file decrypts to the original" '"$SSENC" decrypt --ssh-key tmp/demo_rsa.pub -i tmp/rsa.enc | cmp - tmp/secrets.env'

echo "${0}: Without the key in the agent the file cannot be opened: exit code 4 (ENV)"
run 'ssh-add -q -d tmp/demo_ed25519'
fails 4 '"$SSENC" decrypt --ssh-key tmp/demo_ed25519.pub -i tmp/secrets.env.enc'

echo "${0}: Load the key again and it opens"
run 'ssh-add -q tmp/demo_ed25519'
check "decrypts again" '"$SSENC" decrypt --ssh-key tmp/demo_ed25519.pub -i tmp/secrets.env.enc | cmp - tmp/secrets.env'
