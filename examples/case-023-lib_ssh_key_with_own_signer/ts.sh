#!/usr/bin/env bash
# case-023-lib_ssh_key_with_own_signer, TypeScript library: use an ssh key that is not in ssh-agent by supplying the signature yourself.
# The code to read is demo.ts; Node.js runs it directly, there is no build step.
cd "$(dirname "${BASH_SOURCE[0]}")"
source ../lib/demo.sh
built "$(pwd)/../../typescript/dist/ssenc.node.ts" "typescript/compile.sh"
title "case-023-lib_ssh_key_with_own_signer [ts, library]"
source ./prepare.sh

echo "${0}: a second private key, to show that a different key does not open the text"
run 'openssl genpkey -algorithm ed25519 -out tmp/other_key.pem'

echo "${0}: demo.ts imports the single-file library straight from the repository"
run 'grep "^import.*ssenc" demo.ts'
echo "${0}: run it with Node.js (source: demo.ts)"
run 'node demo.ts'
