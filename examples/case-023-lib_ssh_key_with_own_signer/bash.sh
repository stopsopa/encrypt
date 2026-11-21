#!/usr/bin/env bash
# case-023-lib_ssh_key_with_own_signer, Bash library: use an ssh key that is not in ssh-agent by supplying the signature yourself.
# The library is one file that is sourced; it defines functions and changes nothing else.
cd "$(dirname "${BASH_SOURCE[0]}")"
source ../lib/demo.sh
title "case-023-lib_ssh_key_with_own_signer [bash, library]"
source ./prepare.sh

echo "${0}: load the library: it defines ssenc_encrypt, ssenc_decrypt, ssenc_rekey and ssenc_inspect"
run 'source "$(pwd)/../../bash/ssenc.sh"'

echo "${0}: the TypeScript and Rust libraries accept a 'signer' function in place of ssh-agent (see ts.sh and rust.sh)."
echo "${0}: the Bash library has no such hook: it always gets the signature from an ssh-agent, through ssh-keygen -Y sign."
echo "${0}: what a script can choose is WHICH agent: the one SSH_AUTH_SOCK points at when the function is called."

echo "${0}: so here are two private agents: one holds the demo key, the other is empty"
demo_agent_start
WITH_KEY="$SSH_AUTH_SOCK"
run 'ssh-add -q tmp/demo_ed25519'
echo "\$ ssh-agent -a $DEMO_AGENT_DIR/empty.sock"
EMPTY_AGENT_OUTPUT="$(ssh-agent -a "$DEMO_AGENT_DIR/empty.sock" -s)"
EMPTY_AGENT_PID="$(echo "$EMPTY_AGENT_OUTPUT" | sed -n 's/^SSH_AGENT_PID=\([0-9]*\);.*/\1/p')"
trap 'kill "$EMPTY_AGENT_PID" 2>/dev/null || true; demo_agent_stop' EXIT
EMPTY="$DEMO_AGENT_DIR/empty.sock"

run 'printf "API_KEY=8f2c1d\nDB_PASSWORD=hunter2\n" > tmp/plain.env'
echo "${0}: encrypt and decrypt through the agent that holds the key"
run 'SSH_AUTH_SOCK="$WITH_KEY" ssenc_encrypt --ssh-key tmp/demo_ed25519.pub -i tmp/plain.env -o tmp/secret.enc'
run 'cat tmp/secret.enc'
run 'SSH_AUTH_SOCK="$WITH_KEY" ssenc_decrypt --ssh-key tmp/demo_ed25519.pub -i tmp/secret.enc'

echo "${0}: the same call through the agent without the key: ENV (4)"
fails 4 'SSH_AUTH_SOCK="$EMPTY" ssenc_decrypt --ssh-key tmp/demo_ed25519.pub -i tmp/secret.enc'

echo "${0}: and with no agent at all: ENV (4)"
fails 4 'env -u SSH_AUTH_SOCK bash -c "source \"$(pwd)/../../bash/ssenc.sh\"; ssenc_decrypt --ssh-key tmp/demo_ed25519.pub -i tmp/secret.enc"'

echo "${0}: the key from prepare.sh that is in no agent cannot be used from Bash"
fails 4 'SSH_AUTH_SOCK="$WITH_KEY" ssenc_encrypt --ssh-key tmp/signer_key.pub -i tmp/plain.env -o tmp/other.enc'
