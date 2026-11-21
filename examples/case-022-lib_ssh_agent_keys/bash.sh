#!/usr/bin/env bash
# case-022-lib_ssh_agent_keys, Bash library: ssh keys held by ssh-agent as keys: by public key, by fingerprint, together with a password.
# The library is one file that is sourced; it defines functions and changes nothing else.
cd "$(dirname "${BASH_SOURCE[0]}")"
source ../lib/demo.sh
title "case-022-lib_ssh_agent_keys [bash, library]"
source ./prepare.sh

echo "${0}: load the library: it defines ssenc_encrypt, ssenc_decrypt, ssenc_rekey and ssenc_inspect"
run 'source "$(pwd)/../../bash/ssenc.sh"'

echo "${0}: a private ssh-agent just for this example (your own agent is never used), with both demo keys loaded"
demo_agent_start
run 'ssh-add -q tmp/demo_ed25519 tmp/demo_rsa'
run 'ssh-add -l'
run 'printf "API_KEY=8f2c1d\nDB_PASSWORD=hunter2\n" > tmp/plain.env'

echo "${0}: an ssh key is named by its PUBLIC key file; the private key stays in the agent"
run 'ssenc_encrypt --ssh-key tmp/demo_ed25519.pub -i tmp/plain.env -o tmp/secret.enc'
run 'cat tmp/secret.enc'
run 'ssenc_decrypt --ssh-key tmp/demo_ed25519.pub -i tmp/secret.enc'

echo "${0}: the key can be named by fingerprint alone; it is then looked up in the agent"
run 'FINGERPRINT="$(ssh-keygen -lf tmp/demo_ed25519.pub | awk "{ print \$2 }")"; echo "$FINGERPRINT"'
run 'ssenc_decrypt --ssh-key "$FINGERPRINT" -i tmp/secret.enc'

echo "${0}: the agent is the one SSH_AUTH_SOCK points at; set it for one call to use a specific agent"
run 'SSH_AUTH_SOCK="$DEMO_AGENT_DIR/agent.sock" ssenc_decrypt --ssh-key tmp/demo_ed25519.pub -i tmp/secret.enc'

echo "${0}: several keys: two ssh keys and a backup password; any one opens the text"
run 'ssenc_encrypt --ssh-key tmp/demo_ed25519.pub --ssh-key tmp/demo_rsa.pub --password-file tmp/backup-password.txt -i tmp/plain.env -o tmp/shared.enc'
run 'ssenc_inspect -i tmp/shared.enc'
check "the Ed25519 key opens it" 'ssenc_decrypt --ssh-key tmp/demo_ed25519.pub -i tmp/shared.enc | cmp - tmp/plain.env'
check "the RSA key opens it" 'ssenc_decrypt --ssh-key tmp/demo_rsa.pub -i tmp/shared.enc | cmp - tmp/plain.env'
check "the backup password opens it" 'ssenc_decrypt --password-file tmp/backup-password.txt -i tmp/shared.enc | cmp - tmp/plain.env'

echo "${0}: stable updates work with an ssh key as with a password: one new line, all three key slots kept"
run 'cp tmp/shared.enc tmp/before.enc && echo "REGION=eu-west-1" >> tmp/plain.env'
run 'ssenc_encrypt --ssh-key tmp/demo_rsa.pub -i tmp/plain.env -o tmp/shared.enc'
run 'diff tmp/before.enc tmp/shared.enc || true'
check "three key slots are still there" '[[ "$(grep -c "^#slot" tmp/shared.enc)" == 3 ]]'

echo "${0}: rekey from the password to the ssh key only"
run 'ssenc_rekey --password-file tmp/backup-password.txt --new-ssh-key tmp/demo_ed25519.pub -i tmp/shared.enc -o tmp/only-ssh.enc'
run 'ssenc_inspect -i tmp/only-ssh.enc'
fails 2 'ssenc_decrypt --password-file tmp/backup-password.txt -i tmp/only-ssh.enc'

echo "${0}: a key that is not loaded in the agent: ENV (4)"
fails 4 'ssenc_decrypt --ssh-key "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" -i tmp/secret.enc'
