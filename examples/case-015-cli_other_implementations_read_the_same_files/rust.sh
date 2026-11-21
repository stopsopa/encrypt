#!/usr/bin/env bash
# case-015-cli_other_implementations_read_the_same_files, Rust command line: files made by one implementation are read, updated and rekeyed by the other two.
cd "$(dirname "${BASH_SOURCE[0]}")"
source ../lib/demo.sh
SSENC="$(pwd)/../../rust/target/release/ssenc"   # the binary built by rust/compile.sh
built "$SSENC" "rust/compile.sh"
title "case-015-cli_other_implementations_read_the_same_files [rust, command line]"
source ./prepare.sh

# The two other implementations of the same command.
OTHER_A="$(pwd)/../../typescript/bin/ssenc"   # TypeScript
OTHER_B="$(pwd)/../../bash/bin/ssenc"   # Bash
built "$OTHER_A" "./compile.sh in the repository root"
built "$OTHER_B" "./compile.sh in the repository root"
run '"$SSENC" --version; "$OTHER_A" --version; "$OTHER_B" --version'

echo "${0}: A private ssh-agent just for this example, with the demo key loaded"
demo_agent_start
run 'ssh-add -q tmp/demo_ed25519'

echo "${0}: Encrypt three files with THIS implementation: text with a password, binary with a password, text with an ssh key"
run '"$SSENC" encrypt --password-file tmp/password.txt -i tmp/config.yml -o tmp/config.yml.enc'
run '"$SSENC" encrypt --mode blob --password-file tmp/password.txt -i tmp/photo.bin -o tmp/photo.bin.enc'
run '"$SSENC" encrypt --ssh-key tmp/demo_ed25519.pub -i tmp/config.yml -o tmp/config.ssh.enc'

echo "${0}: TypeScript decrypts all three"
run '"$OTHER_A" decrypt --password-file tmp/password.txt -i tmp/config.yml.enc'
run '"$OTHER_A" decrypt --password-file tmp/password.txt -i tmp/photo.bin.enc | cmp - tmp/photo.bin && echo "binary file identical"'
run '"$OTHER_A" decrypt --ssh-key tmp/demo_ed25519.pub -i tmp/config.ssh.enc | cmp - tmp/config.yml && echo "ssh-encrypted file identical"'

echo "${0}: Bash decrypts all three"
run '"$OTHER_B" decrypt --password-file tmp/password.txt -i tmp/config.yml.enc'
run '"$OTHER_B" decrypt --password-file tmp/password.txt -i tmp/photo.bin.enc | cmp - tmp/photo.bin && echo "binary file identical"'
run '"$OTHER_B" decrypt --ssh-key tmp/demo_ed25519.pub -i tmp/config.ssh.enc | cmp - tmp/config.yml && echo "ssh-encrypted file identical"'

echo "${0}: Stable diffs work across implementations: TypeScript updates the file this one made, one line changes"
run 'cp tmp/config.yml.enc tmp/before.enc'
run 'sed "s/port: 5432/port: 6543/" tmp/config.yml > tmp/config.new && mv tmp/config.new tmp/config.yml'
run '"$OTHER_A" encrypt --password-file tmp/password.txt -i tmp/config.yml -o tmp/config.yml.enc'
run 'diff tmp/before.enc tmp/config.yml.enc || true'
check "exactly one line changed" '[[ "$(diff tmp/before.enc tmp/config.yml.enc | grep -c "^>")" == 1 ]]'

echo "${0}: Bash changes the key (password -> ssh key), this implementation reads the result"
run '"$OTHER_B" rekey --password-file tmp/password.txt --new-ssh-key tmp/demo_ed25519.pub -i tmp/config.yml.enc -o tmp/config.yml.enc'
run '"$SSENC" inspect -i tmp/config.yml.enc'
run '"$SSENC" decrypt --ssh-key tmp/demo_ed25519.pub -i tmp/config.yml.enc'
check "the content is the updated file" '"$SSENC" decrypt --ssh-key tmp/demo_ed25519.pub -i tmp/config.yml.enc | cmp - tmp/config.yml'
