#!/usr/bin/env bash
# case-022-lib_ssh_agent_keys, TypeScript library: ssh keys held by ssh-agent as keys: by public key, by fingerprint, together with a password.
# The code to read is demo.ts; Node.js runs it directly, there is no build step.
cd "$(dirname "${BASH_SOURCE[0]}")"
source ../lib/demo.sh
built "$(pwd)/../../typescript/dist/ssenc.node.ts" "typescript/compile.sh"
title "case-022-lib_ssh_agent_keys [ts, library]"
source ./prepare.sh

echo "${0}: a private ssh-agent just for this example (your own agent is never used), with both demo keys loaded"
demo_agent_start
run 'ssh-add -q tmp/demo_ed25519 tmp/demo_rsa'
run 'ssh-add -l'

echo "${0}: demo.ts imports the single-file library straight from the repository"
run 'grep "^import.*ssenc" demo.ts'
echo "${0}: run it with Node.js (source: demo.ts)"
run 'node demo.ts'
