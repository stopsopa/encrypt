#!/usr/bin/env bash
# case-018-lib_files_text_and_binary, TypeScript library: encrypt a text file line by line and a binary file as a blob, inspect and decrypt them.
# The code to read is demo.ts; Node.js runs it directly, there is no build step.
cd "$(dirname "${BASH_SOURCE[0]}")"
source ../lib/demo.sh
built "$(pwd)/../../typescript/dist/ssenc.node.ts" "typescript/compile.sh"
title "case-018-lib_files_text_and_binary [ts, library]"
source ./prepare.sh

echo "${0}: demo.ts imports the single-file library straight from the repository"
run 'grep "^import.*ssenc" demo.ts'
echo "${0}: run it with Node.js (source: demo.ts)"
run 'node demo.ts'
