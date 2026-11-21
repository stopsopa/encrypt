#!/usr/bin/env bash
# case-001-cli_text_with_password, Rust command line: encrypt a text with a password and decrypt it again (stdin -> stdout).
cd "$(dirname "${BASH_SOURCE[0]}")"
source ../lib/demo.sh
SSENC="$(pwd)/../../rust/target/release/ssenc"   # the binary built by rust/compile.sh
built "$SSENC" "rust/compile.sh"
title "case-001-cli_text_with_password [rust, command line]"
source ./prepare.sh

echo "${0}: The password is taken from the environment variable SSENC_PASSWORD (never from an argument)"
run 'export SSENC_PASSWORD="$(cat tmp/password.txt)"'

echo "${0}: Encrypt: plain text on standard input -> encrypted ASCII text on standard output"
run 'echo "my first secret" | "$SSENC" encrypt'

echo "${0}: The same, kept in a file"
run 'echo "my first secret" | "$SSENC" encrypt > tmp/secret.enc'
run 'cat tmp/secret.enc'

echo "${0}: Decrypt: encrypted text on standard input -> plain text on standard output"
run '"$SSENC" decrypt < tmp/secret.enc'

echo "${0}: Several lines: every line of the input becomes one line of the output"
run 'printf "user: admin\npassword: hunter2\nport: 5432\n" | "$SSENC" encrypt > tmp/three.enc'
run 'cat tmp/three.enc'
run '"$SSENC" decrypt < tmp/three.enc'

echo "${0}: Encrypted text pasted straight into a script (heredoc)"
run '"$SSENC" decrypt <<END_OF_SECRET
$(cat tmp/secret.enc)
END_OF_SECRET'

check "the decrypted text equals the original" '[[ "$("$SSENC" decrypt < tmp/secret.enc)" == "my first secret" ]]'
