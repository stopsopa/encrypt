#!/usr/bin/env bash
# case-008-cli_password_cost_kdf, TypeScript (Node.js) command line: set how expensive the password-to-key step is (--kdf).
cd "$(dirname "${BASH_SOURCE[0]}")"
source ../lib/demo.sh
SSENC="$(pwd)/../../typescript/bin/ssenc"   # runs typescript/dist/cli.ts with node
built "$SSENC" "typescript/compile.sh"
title "case-008-cli_password_cost_kdf [ts, command line]"
source ./prepare.sh

echo "${0}: Turning a password into a key is slow on purpose (Argon2id), so that guessing passwords is expensive."
echo "${0}: Default cost: 64 MiB of memory, 3 passes"
timed '"$SSENC" encrypt --password-file tmp/password.txt -i tmp/secret.txt -o tmp/default.enc'
run '"$SSENC" inspect -i tmp/default.enc'

echo "${0}: --kdf m=<KiB>,t=<passes>,p=<lanes> sets the cost: here 256 MiB and 2 passes"
timed '"$SSENC" encrypt --kdf m=262144,t=2,p=4 --password-file tmp/password.txt -i tmp/secret.txt -o tmp/custom.enc'
run '"$SSENC" inspect -i tmp/custom.enc'

echo "${0}: A lower cost, e.g. for a slow machine: 19 MiB, 2 passes, 1 lane"
timed '"$SSENC" encrypt --kdf m=19456,t=2,p=1 --password-file tmp/password.txt -i tmp/secret.txt -o tmp/low.enc'

echo "${0}: The cost is written into the file (see the #slot line), so decrypting needs no option"
run 'grep "^#slot" tmp/default.enc tmp/custom.enc tmp/low.enc | cut -c 1-60'
timed '"$SSENC" decrypt --password-file tmp/password.txt -i tmp/custom.enc'
timed '"$SSENC" decrypt --password-file tmp/password.txt -i tmp/low.enc'

echo "${0}: There is also '--kdf strong' (1 GiB, 4 passes). It is not run here because it needs 1 GiB of memory:"
echo '$ "$SSENC" encrypt --kdf strong --password-file tmp/password.txt -i tmp/secret.txt -o tmp/strong.enc'

echo "${0}: A cost outside the allowed range is refused"
fails 1 '"$SSENC" encrypt --kdf m=1,t=1,p=1 --password-file tmp/password.txt -i tmp/secret.txt -o tmp/bad.enc'

check "the file with the custom cost records it" '"$SSENC" inspect -i tmp/custom.enc | grep -q "\"m\":262144,\"t\":2,\"p\":4"'
