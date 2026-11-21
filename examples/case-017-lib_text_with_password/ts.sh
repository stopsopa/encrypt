#!/usr/bin/env bash
# case-017-lib_text_with_password, TypeScript library: encrypt and decrypt a text with a password.
# The code to read is demo.ts; Node.js runs it directly, there is no build step.
cd "$(dirname "${BASH_SOURCE[0]}")"
source ../lib/demo.sh
built "$(pwd)/../../typescript/dist/ssenc.node.ts" "typescript/compile.sh"
title "case-017-lib_text_with_password [ts, library]"
source ./prepare.sh

echo "${0}: demo.ts imports the single-file library straight from the repository"
run 'grep "^import.*ssenc" demo.ts'
echo "${0}: run it with Node.js (source: demo.ts)"
run 'node demo.ts'

echo "${0}: the same library exists as plain JavaScript and as a browser build; demo-js.mjs uses both"
run 'ls "$(pwd)/../../typescript/dist"'
run 'node demo-js.mjs'
