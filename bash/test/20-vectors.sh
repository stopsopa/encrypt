#!/usr/bin/env bash
# File vectors of tests/vectors opened by a password, in both directions:
#     decrypt(encrypted.txt) == plain.bin
#     encrypt(plain.bin, --previous encrypted.txt) == encrypted.txt   (byte for byte)
# plus inspect and the library functions. (ssh-keyed vectors: 40-ssh.sh)
# shellcheck source=helpers.bash
source "$(dirname "${BASH_SOURCE[0]}")/helpers.bash"

t_load_vectors
count=0
for i in "${!V_NAME[@]}"; do
  [[ ${V_KIND[i]} == password ]] || continue
  name=${V_NAME[i]}
  dir="$T_VECTORS/$name"
  export SSENC_PASSWORD="${V_KEY[i]}"
  count=$((count + 1))

  "$T_SSENC" decrypt -i "$dir/encrypted.txt" -o "$T_TMP/plain" 2>"$T_TMP/err"
  t_same "$name: decrypt == plain.bin" "$T_TMP/plain" "$dir/plain.bin"

  "$T_SSENC" encrypt --previous "$dir/encrypted.txt" -i "$dir/plain.bin" -o "$T_TMP/enc" 2>"$T_TMP/err"
  t_same "$name: encrypt --previous == encrypted.txt" "$T_TMP/enc" "$dir/encrypted.txt"

  # the same through the library functions, stdin -> stdout
  ssenc_decrypt <"$dir/encrypted.txt" >"$T_TMP/plain2" 2>"$T_TMP/err"
  t_same "$name: ssenc_decrypt (library)" "$T_TMP/plain2" "$dir/plain.bin"
  ssenc_encrypt --previous "$dir/encrypted.txt" <"$dir/plain.bin" >"$T_TMP/enc2" 2>"$T_TMP/err"
  t_same "$name: ssenc_encrypt --previous (library)" "$T_TMP/enc2" "$dir/encrypted.txt"

  # auto-previous: -o names an existing ssenc1 file
  cp "$dir/encrypted.txt" "$T_TMP/auto"
  "$T_SSENC" encrypt -i "$dir/plain.bin" -o "$T_TMP/auto" 2>"$T_TMP/err"
  t_same "$name: encrypt onto the existing file reuses its key" "$T_TMP/auto" "$dir/encrypted.txt"

  SSENC_PASSWORD="not the password" t_code "$name: wrong password -> AUTH" 2 "$T_SSENC" decrypt -i "$dir/encrypted.txt"
done
unset SSENC_PASSWORD
t_eq "found the password vectors" "$((count >= 9))" "1"

t_eq "inspect lines-default" "$("$T_SSENC" inspect -i "$T_VECTORS/lines-default/encrypted.txt")" \
  '{"format":"ssenc1","mode":"lines","ws":true,"pad":16,"seal":false,"slots":[{"type":"pw","kdf":"argon2id","m":8192,"t":1,"p":1}]}'
t_eq "inspect lines-ws0-pad0-seal" "$(ssenc_inspect <"$T_VECTORS/lines-ws0-pad0-seal/encrypted.txt")" \
  '{"format":"ssenc1","mode":"lines","ws":false,"pad":0,"seal":true,"slots":[{"type":"pw","kdf":"argon2id","m":8192,"t":1,"p":1}]}'
t_eq "inspect blob-small-chunks" "$("$T_SSENC" inspect <"$T_VECTORS/blob-small-chunks/encrypted.txt")" \
  '{"format":"ssenc1","mode":"blob","chunk":64,"slots":[{"type":"pw","kdf":"argon2id","m":8192,"t":1,"p":1}]}'
t_eq "inspect lines-pad1-multislot" "$("$T_SSENC" inspect -i "$T_VECTORS/lines-pad1-multislot/encrypted.txt")" \
  '{"format":"ssenc1","mode":"lines","ws":true,"pad":1,"seal":false,"slots":[{"type":"pw","kdf":"argon2id","m":64,"t":2,"p":4},{"type":"ssh","keyType":"ssh-ed25519","fingerprint":"SHA256:4IB5jiYanewMywAI1mGNXatXdiZkyb8ki3to5sgdkSk"},{"type":"ssh","keyType":"ssh-rsa","fingerprint":"SHA256:x0ZnS0agFoE2/hfbRXJ4hHYiaSxSXDfgp7fcl2QBh8c"}]}'

t_done
