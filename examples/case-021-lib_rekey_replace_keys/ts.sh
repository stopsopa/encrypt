#!/usr/bin/env bash
# case-021-lib_rekey_replace_keys, TypeScript library: replace the keys of an encrypted text, with or without a new data key.
# The code to read is demo.ts; Node.js runs it directly, there is no build step.
cd "$(dirname "${BASH_SOURCE[0]}")"
source ../lib/demo.sh
built "$(pwd)/../../typescript/dist/ssenc.node.ts" "typescript/compile.sh"
title "case-021-lib_rekey_replace_keys [ts, library]"
source ./prepare.sh

echo "${0}: demo.ts imports the single-file library straight from the repository"
run 'grep "^import.*ssenc" demo.ts'
echo "${0}: run it with Node.js (source: demo.ts)"
run 'node demo.ts'
