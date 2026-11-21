#!/usr/bin/env bash
# case-006-cli_whitespace_and_padding, Rust command line: choose whether indentation stays readable and how much line lengths reveal.
cd "$(dirname "${BASH_SOURCE[0]}")"
source ../lib/demo.sh
SSENC="$(pwd)/../../rust/target/release/ssenc"   # the binary built by rust/compile.sh
built "$SSENC" "rust/compile.sh"
title "case-006-cli_whitespace_and_padding [rust, command line]"
source ./prepare.sh

echo "${0}: Default: leading and trailing spaces/tabs stay as they are, lines are padded to a multiple of 16 bytes"
run '"$SSENC" encrypt --password-file tmp/password.txt -i tmp/app.yml -o tmp/default.enc'
run 'cat tmp/default.enc'

echo "${0}: --no-preserve-ws: the indentation is encrypted too (an empty line becomes a token as well)"
run '"$SSENC" encrypt --no-preserve-ws --password-file tmp/password.txt -i tmp/app.yml -o tmp/nows.enc'
run 'cat tmp/nows.enc'

echo "${0}: --pad 0: no padding, the length of every encrypted line follows the length of the plain line exactly"
run '"$SSENC" encrypt --pad 0 --password-file tmp/password.txt -i tmp/app.yml -o tmp/pad0.enc'
run 'cat tmp/pad0.enc'

echo "${0}: --pad 128: all lines up to 127 bytes get the same length, so lengths reveal nothing"
run '"$SSENC" encrypt --pad 128 --no-preserve-ws --password-file tmp/password.txt -i tmp/app.yml -o tmp/pad128.enc'
run 'cut -c 1-60 tmp/pad128.enc'
run 'tail -n +3 tmp/pad128.enc | awk "{ print length(\$0) }" | sort -u'

echo "${0}: The settings are stored in the first line, so decrypting needs no options"
run 'head -n 1 tmp/default.enc tmp/nows.enc tmp/pad0.enc tmp/pad128.enc'
for f in default nows pad0 pad128; do
  check "$f.enc decrypts to the original" "\"\$SSENC\" decrypt --password-file tmp/password.txt -i tmp/$f.enc | cmp - tmp/app.yml"
done
