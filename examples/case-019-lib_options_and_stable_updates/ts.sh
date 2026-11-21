#!/usr/bin/env bash
# case-019-lib_options_and_stable_updates, TypeScript library: every option of encrypt (cost, whitespace, padding, seal) and updates that change only the edited lines.
# The code to read is demo.ts; Node.js runs it directly, there is no build step.
cd "$(dirname "${BASH_SOURCE[0]}")"
source ../lib/demo.sh
built "$(pwd)/../../typescript/dist/ssenc.node.ts" "typescript/compile.sh"
title "case-019-lib_options_and_stable_updates [ts, library]"
source ./prepare.sh

echo "${0}: demo.ts imports the single-file library straight from the repository"
run 'grep "^import.*ssenc" demo.ts'
echo "${0}: run it with Node.js (source: demo.ts)"
run 'node demo.ts'
