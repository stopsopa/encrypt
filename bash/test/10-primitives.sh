#!/usr/bin/env bash
# Every entry of tests/vectors/primitives.json: HKDF32, SIV (both directions), Argon2id.
# shellcheck source=helpers.bash
source "$(dirname "${BASH_SOURCE[0]}")/helpers.bash"

# The file is JSON.stringify(x, null, 2) output: one '"key": value' per line, objects of
# an array closed by a line holding only "}" or "},". That is all this parser relies on.
section=
n=0
f_ikm='' f_salt='' f_info='' f_out='' f_parent='' f_purpose='' f_ad='' f_pt='' f_kmac='' f_kenc='' f_password='' f_m='' f_t='' f_p=

run_entry() {
  local got pwhex
  n=$((n + 1))
  case $section in
    hkdf32)
      got=$(ssenc_hkdf32 "$f_ikm" "$f_salt" "$f_info")
      t_eq "hkdf32 #$n info=$f_info salt=${f_salt:+given}${f_salt:+.}" "$got" "$f_out"
      ;;
    siv)
      got=$(ssenc_sivkey "$f_parent" "$f_purpose")
      t_eq "siv #$n subkeys of purpose '$f_purpose'" "$got" "$f_kmac $f_kenc"
      got=$(ssenc_siv_encrypt "$f_kmac" "$f_kenc" "$f_ad" "$f_pt")
      t_eq "siv #$n encrypt (${#f_pt} hex chars, ad '$f_ad')" "$got" "$f_out"
      got=$(ssenc_siv_decrypt "$f_kmac" "$f_kenc" "$f_ad" "$f_out")
      t_eq "siv #$n decrypt" "$got" "$f_pt"
      ;;
    argon2id)
      pwhex=$(printf '%s' "$f_password" | xxd -p | tr -d '\n')
      got=$(ssenc_argon2id "$pwhex" "$f_salt" "$f_m" "$f_t" "$f_p")
      t_eq "argon2id #$n m=$f_m,t=$f_t,p=$f_p" "$got" "$f_out"
      ;;
  esac
}

while IFS= read -r line; do
  if [[ $line =~ ^\ \ \"([a-z0-9]+)\":\ \[ ]]; then
    section=${BASH_REMATCH[1]}
    n=0
  elif [[ $line =~ ^\ +\"([a-zA-Z0-9]+)\":\ (.*)$ ]]; then
    key=${BASH_REMATCH[1]}
    val=${BASH_REMATCH[2]}
    val=${val%,}
    if [[ $val == null ]]; then
      val=
    else
      val=${val#\"}
      val=${val%\"}
    fi
    printf -v "f_$key" '%s' "$val"
  elif [[ $line =~ ^\ +\},?$ ]]; then
    run_entry
  fi
done <"$T_VECTORS/primitives.json"

# negative cases of the primitives
k1=$(printf '%064x' 1)
k2=$(printf '%064x' 2)
ct=$(ssenc_siv_encrypt "$k1" "$k2" "aa" "68656c6c6f")
t_eq "siv: output is 16 bytes longer than the input" "${#ct}" "42"
t_code "siv: modified ciphertext -> AUTH" 2 ssenc_siv_decrypt "$k1" "$k2" "aa" "${ct%??}00"
t_code "siv: modified tag -> AUTH" 2 ssenc_siv_decrypt "$k1" "$k2" "aa" "00${ct:2}"
t_code "siv: other associated data -> AUTH" 2 ssenc_siv_decrypt "$k1" "$k2" "ab" "$ct"
t_code "siv: wrong mac key -> AUTH" 2 ssenc_siv_decrypt "$k2" "$k2" "aa" "$ct"
t_code "siv: input shorter than a tag -> MALFORMED" 3 ssenc_siv_decrypt "$k1" "$k2" "" "00112233"
t_eq "siv: deterministic" "$(ssenc_siv_encrypt "$k1" "$k2" "aa" "68656c6c6f")" "$ct"
# 3 blocks + 1 byte, exercises the counter increment across blocks
long=$(printf '%098x' 7)
t_eq "siv: multi-block round trip" "$(ssenc_siv_decrypt "$k1" "$k2" "" "$(ssenc_siv_encrypt "$k1" "$k2" "" "$long")")" "$long"

t_done
