#!/usr/bin/env bash
# ssh-agent slots. Uses ONLY the throwaway agent of tests/lib/agent.sh (repository test
# keys); the developer's own agent is never contacted: SSH_AUTH_SOCK is unset before the
# throwaway agent is started and every test is skipped if that agent did not come up.
# shellcheck source=helpers.bash
source "$(dirname "${BASH_SOURCE[0]}")/helpers.bash"

unset SSH_AUTH_SOCK SSH_AGENT_PID SSENC_AGENT_DIR SSENC_PASSWORD SSENC_NEW_PASSWORD
AGENT="$T_ROOT/tests/lib/agent.sh"

stop_agent() {
  if [[ -n ${SSENC_AGENT_DIR:-} ]]; then
    "$AGENT" stop >/dev/null 2>&1
    unset SSENC_AGENT_DIR SSH_AUTH_SOCK SSH_AGENT_PID
  fi
  t_cleanup
}
trap stop_agent EXIT
trap 'exit 130' INT TERM

if ! command -v ssh-agent >/dev/null 2>&1 || ! command -v ssh-add >/dev/null 2>&1 || ! command -v ssh-keygen >/dev/null 2>&1; then
  echo "skip - ssh-agent / ssh-add / ssh-keygen not installed"
  t_done
  exit $?
fi
assignments="$("$AGENT" start 2>"$T_TMP/agent.err")"
if [[ -n $assignments ]]; then eval "$assignments"; fi
if [[ -z ${SSENC_AGENT_DIR:-} || ${SSH_AUTH_SOCK:-} != "$SSENC_AGENT_DIR/a" ]]; then
  unset SSH_AUTH_SOCK SSH_AGENT_PID SSENC_AGENT_DIR
  echo "skip - the throwaway ssh-agent could not be started: $(head -n 1 "$T_TMP/agent.err")"
  t_done
  exit $?
fi

ED="$T_KEYS/test_ed25519.pub"
RSA="$T_KEYS/test_rsa.pub"
ECDSA="$T_KEYS/test_ecdsa.pub"
ABSENT="$T_KEYS/test_absent.pub"
fp() { ssh-keygen -lf "$1" | sed -e 's/^[0-9]* \([^ ]*\) .*/\1/'; }
ED_FP=$(fp "$ED")
RSA_FP=$(fp "$RSA")

# ---- vectors --------------------------------------------------------------------------
vector() { # NAME KEYFILE
  local name=$1 key=$2 dir="$T_VECTORS/$1" label
  label="$name with $(basename "$key")"
  "$T_SSENC" decrypt --ssh-key "$key" -i "$dir/encrypted.txt" -o "$T_TMP/plain" 2>"$T_TMP/err"
  t_same "$label: decrypt == plain.bin" "$T_TMP/plain" "$dir/plain.bin"
  "$T_SSENC" encrypt --ssh-key "$key" --previous "$dir/encrypted.txt" -i "$dir/plain.bin" -o "$T_TMP/enc" 2>"$T_TMP/err"
  t_same "$label: encrypt --previous == encrypted.txt" "$T_TMP/enc" "$dir/encrypted.txt"
}
t_load_vectors
for i in "${!V_NAME[@]}"; do
  [[ ${V_KIND[i]} == ssh ]] || continue
  vector "${V_NAME[i]}" "$T_KEYS/${V_KEY[i]}.pub"
done
vector lines-pad1-multislot "$ED"
vector lines-pad1-multislot "$RSA"

"$T_SSENC" decrypt --ssh-key "$ED_FP" -i "$T_VECTORS/lines-ssh-ed25519/encrypted.txt" -o "$T_TMP/plain" 2>"$T_TMP/err"
t_same "fingerprint form of --ssh-key (ed25519)" "$T_TMP/plain" "$T_VECTORS/lines-ssh-ed25519/plain.bin"
"$T_SSENC" decrypt --ssh-key "$RSA_FP" -i "$T_VECTORS/blob-ssh-rsa/encrypted.txt" -o "$T_TMP/plain" 2>"$T_TMP/err"
t_same "fingerprint form of --ssh-key (rsa)" "$T_TMP/plain" "$T_VECTORS/blob-ssh-rsa/plain.bin"

# ---- round trips ----------------------------------------------------------------------
printf 'secret: 1\n  nested: 2\n' >"$T_TMP/in"
"$T_SSENC" encrypt --ssh-key "$ED" -i "$T_TMP/in" -o "$T_TMP/ed.enc"
t_eq "encrypt with an ed25519 key: slot line" "$(sed -n 2p "$T_TMP/ed.enc" | cut -d' ' -f1-4)" "#slot ssh ssh-ed25519 $ED_FP"
"$T_SSENC" decrypt --ssh-key "$ED_FP" -i "$T_TMP/ed.enc" -o "$T_TMP/out"
t_same "ed25519 round trip (file to encrypt, fingerprint to decrypt)" "$T_TMP/out" "$T_TMP/in"
t_code "another key of the agent does not open it -> AUTH" 2 "$T_SSENC" decrypt --ssh-key "$RSA" -i "$T_TMP/ed.enc"

SSENC_PASSWORD=pw "$T_SSENC" encrypt --kdf "$T_KDF" --ssh-key "$RSA_FP" --ssh-key "$ED" --mode blob -i "$T_TMP/in" -o "$T_TMP/multi.enc"
t_eq "slots: password first, then ssh keys in the given order" "$(sed -n '2,4p' "$T_TMP/multi.enc" | cut -d' ' -f2,3 | tr '\n' ',')" "pw argon2id,ssh ssh-rsa,ssh ssh-ed25519,"
for k in "$RSA" "$ED" "$RSA_FP"; do
  "$T_SSENC" decrypt --ssh-key "$k" -i "$T_TMP/multi.enc" -o "$T_TMP/out"
  t_same "multi-slot file opens with ${k##*/}" "$T_TMP/out" "$T_TMP/in"
done
SSENC_PASSWORD=pw "$T_SSENC" decrypt -i "$T_TMP/multi.enc" -o "$T_TMP/out"
t_same "multi-slot file opens with the password" "$T_TMP/out" "$T_TMP/in"

SSENC_NEW_PASSWORD=new "$T_SSENC" rekey --kdf "$T_KDF" --ssh-key "$ED" --new-ssh-key "$RSA" -i "$T_TMP/ed.enc" -o "$T_TMP/rk.enc"
t_eq "rekey from an ssh key to password + ssh key" "$(sed -n '2,3p' "$T_TMP/rk.enc" | cut -d' ' -f2,3 | tr '\n' ',')" "pw argon2id,ssh ssh-rsa,"
"$T_SSENC" decrypt --ssh-key "$RSA" -i "$T_TMP/rk.enc" -o "$T_TMP/out"
t_same "rekeyed file opens with the new ssh key" "$T_TMP/out" "$T_TMP/in"
t_code "rekeyed file no longer opens with the old ssh key -> AUTH" 2 "$T_SSENC" decrypt --ssh-key "$ED" -i "$T_TMP/rk.enc"
"$T_SSENC" rekey --rewrap-only --ssh-key "$ED" --new-ssh-key "$RSA_FP" -i "$T_TMP/ed.enc" -o "$T_TMP/rw.enc"
"$T_SSENC" decrypt --ssh-key "$RSA" -i "$T_TMP/rw.enc" -o "$T_TMP/out"
t_same "rekey --rewrap-only to another ssh key" "$T_TMP/out" "$T_TMP/in"

# ---- environment errors ---------------------------------------------------------------
t_code "ecdsa key -> ENV" 4 "$T_SSENC" encrypt --ssh-key "$ECDSA" -i "$T_TMP/in"
t_code "ecdsa key by fingerprint -> ENV" 4 "$T_SSENC" encrypt --ssh-key "$(fp "$ECDSA")" -i "$T_TMP/in"
t_code "key that is not in the agent (encrypt) -> ENV" 4 "$T_SSENC" encrypt --ssh-key "$ABSENT" -i "$T_TMP/in"
t_code "key that is not in the agent (fingerprint) -> ENV" 4 "$T_SSENC" encrypt --ssh-key "$(fp "$ABSENT")" -i "$T_TMP/in"
printf 'not a key\n' >"$T_TMP/notakey.pub"
t_code "file that is not a public key -> ENV" 4 "$T_SSENC" encrypt --ssh-key "$T_TMP/notakey.pub" -i "$T_TMP/in"
SSH_AUTH_SOCK=/nonexistent t_code "unreachable agent (encrypt) -> ENV" 4 "$T_SSENC" encrypt --ssh-key "$ED" -i "$T_TMP/in"
SSH_AUTH_SOCK=/nonexistent t_code "unreachable agent (decrypt) -> ENV" 4 "$T_SSENC" decrypt --ssh-key "$ED" -i "$T_TMP/ed.enc"
SSH_AUTH_SOCK=/nonexistent t_code "unreachable agent (fingerprint) -> ENV" 4 "$T_SSENC" decrypt --ssh-key "$ED_FP" -i "$T_TMP/ed.enc"
t_code "SSH_AUTH_SOCK not set -> ENV" 4 env -u SSH_AUTH_SOCK "$T_SSENC" decrypt --ssh-key "$ED" -i "$T_TMP/ed.enc"

t_done
