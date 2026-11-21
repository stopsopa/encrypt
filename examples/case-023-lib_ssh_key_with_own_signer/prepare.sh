#!/usr/bin/env bash
# Sourced by rust.sh, ts.sh and bash.sh (and it can be run on its own): starts from an empty
# ./tmp and generates an Ed25519 private key that lives in a plain PEM file (standing in for
# a key in a vault, an HSM or a cloud key service), its public key in OpenSSH format, and an
# ordinary ssh key for the Bash variant.
cd "$(dirname "${BASH_SOURCE[0]}")"
declare -F run > /dev/null || source ../lib/demo.sh
rm -rf tmp && mkdir tmp

if ! openssl genpkey -algorithm ed25519 > /dev/null 2>&1; then
  echo "${0}: EXAMPLE CANNOT RUN: this 'openssl' ($(openssl version)) cannot make Ed25519 keys; OpenSSL >= 1.1.1 is needed in PATH" >&2
  exit 4
fi

echo "${0}: prepare: an Ed25519 private key that is NOT in any ssh-agent (PEM file made by openssl)"
run 'openssl genpkey -algorithm ed25519 -out tmp/signer_key.pem'

echo "${0}: prepare: its public key as an OpenSSH line: 'ssh-ed25519 ' + base64( string('ssh-ed25519') + string(32 key bytes) )"
run '{
  printf "ssh-ed25519 "
  { printf "\000\000\000\013ssh-ed25519\000\000\000\040"; openssl pkey -in tmp/signer_key.pem -pubout -outform DER | tail -c 32; } | base64 | tr -d "\n"
  printf " demo signer key\n"
} > tmp/signer_key.pub'
run 'cat tmp/signer_key.pub'
run 'ssh-keygen -lf tmp/signer_key.pub'

echo "${0}: prepare: an ordinary ssh key (only the Bash variant uses it)"
run 'ssh-keygen -q -t ed25519 -N "" -C "demo ed25519" -f tmp/demo_ed25519'
