#!/usr/bin/env bash
# case-024-lib_many_encryptions_fast, TypeScript library: encrypt, decrypt and update many files quickly from a program.
# The code to read is demo.ts; Node.js runs it directly, there is no build step.
cd "$(dirname "${BASH_SOURCE[0]}")"
source ../lib/demo.sh
built "$(pwd)/../../typescript/dist/ssenc.node.ts" "typescript/compile.sh"
title "case-024-lib_many_encryptions_fast [ts, library]"
source ./prepare.sh

echo "${0}: demo.ts imports the single-file library straight from the repository"
run 'grep "^import.*ssenc" demo.ts'
echo "${0}: run it with Node.js (source: demo.ts)"
run 'node demo.ts'
