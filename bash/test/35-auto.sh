#!/usr/bin/env bash
# --mode auto: lines for text (no NUL byte, valid UTF-8), blob for anything else. The
# inputs and the expected choice are in tests/vectors/auto-mode.json, shared by all
# implementations.
# shellcheck source=helpers.bash
source "$(dirname "${BASH_SOURCE[0]}")/helpers.bash"

export SSENC_PASSWORD="auto mode password"
enc() { "$T_SSENC" encrypt --kdf "$T_KDF" "$@"; }
dec() { "$T_SSENC" decrypt "$@"; }
mode_of() { head -n 1 "$1" | cut -d ' ' -f 2; }
I="$T_TMP/in"
mkdir "$I"

# ---- the shared vectors, through the detection function ------------------------------
re='"name": "([^"]*)", "hex": "([^"]*)", "mode": "([^"]*)"'
lines=0
blobs=0
names=() wants=()
while IFS= read -r line; do
  [[ $line =~ $re ]] || continue
  name=${BASH_REMATCH[1]} want=${BASH_REMATCH[3]}
  printf '%s' "${BASH_REMATCH[2]}" | xxd -r -p >"$I/$name"
  names+=("$name") wants+=("$want")
  _ssenc_detect_mode "$I/$name"
  t_eq "detect: $name -> $want" "$_MODE" "$want"
  if [[ $want == lines ]]; then lines=$((lines + 1)); else blobs=$((blobs + 1)); fi
done <"$T_VECTORS/auto-mode.json"
if ((lines >= 15 && blobs >= 20)); then
  t_ok "auto-mode.json has enough text and binary inputs"
else
  t_fail "auto-mode.json has enough text and binary inputs" "$lines text, $blobs binary"
fi

# ---- a few of them through the command line: header and round trip ---------------------
i=0
while ((i < ${#names[@]})); do
  name=${names[i]} want=${wants[i]}
  i=$((i + 1))
  case $name in
    empty | ascii | utf8-mixed-lines | utf8-bom | nul-inside-text | latin1-text | sequence-inside-a-sequence | sequence-split-by-newline | png-signature) ;;
    *) continue ;;
  esac
  enc --mode auto -i "$I/$name" -o "$T_TMP/a.enc" --fresh 2>"$T_TMP/err"
  t_eq "encrypt --mode auto: $name is a $want file" "$(mode_of "$T_TMP/a.enc")" "$want"
  dec -i "$T_TMP/a.enc" -o "$T_TMP/a.dec" 2>>"$T_TMP/err"
  t_same "encrypt --mode auto: $name round trip" "$T_TMP/a.dec" "$I/$name"
done

# ---- the whole input is examined, not only its beginning -------------------------------
{
  head -c 200000 /dev/zero | tr '\0' 'x' | fold -w 100
  printf 'za\305\274\303\263\305\202\304\207 \342\210\236\n'
} >"$I/long-text"
{
  cat "$I/long-text"
  printf 'late bad byte \377\n'
} >"$I/long-binary"
_ssenc_detect_mode "$I/long-text"
t_eq "detect: 200 kB of text with UTF-8 at the end -> lines" "$_MODE" "lines"
_ssenc_detect_mode "$I/long-binary"
t_eq "detect: the same with one bad byte at the very end -> blob" "$_MODE" "blob"
head -c 4096 /dev/urandom >"$I/random"
printf '\000' >>"$I/random"
_ssenc_detect_mode "$I/random"
t_eq "detect: random bytes -> blob" "$_MODE" "blob"

# ---- an existing file keeps its mode -------------------------------------------------
printf 'a\nb\n' >"$I/text"
printf 'a\n\377\000\n' >"$I/binary"
enc --mode auto -i "$I/text" -o "$T_TMP/keep.enc" --fresh
cp "$T_TMP/keep.enc" "$T_TMP/keep.v1"
t_eq "text is encrypted in lines mode" "$(mode_of "$T_TMP/keep.enc")" "lines"
enc --mode auto -i "$I/binary" -o "$T_TMP/keep.enc"
t_eq "existing lines file + binary content: stays lines" "$(mode_of "$T_TMP/keep.enc")" "lines"
t_eq "... and only the edited line changed" "$(diff "$T_TMP/keep.v1" "$T_TMP/keep.enc" | grep -c '^>')" "1"
dec -i "$T_TMP/keep.enc" -o "$T_TMP/keep.dec"
t_same "... and it decrypts to the binary content" "$T_TMP/keep.dec" "$I/binary"
enc --mode auto --previous "$T_TMP/keep.v1" -i "$I/binary" -o "$T_TMP/other.enc"
t_eq "--previous lines file + binary content: stays lines" "$(mode_of "$T_TMP/other.enc")" "lines"
enc --mode auto --fresh -i "$I/binary" -o "$T_TMP/keep.enc"
t_eq "--fresh detects again: binary content -> blob" "$(mode_of "$T_TMP/keep.enc")" "blob"
enc --mode auto -i "$I/text" -o "$T_TMP/keep.enc"
t_eq "existing blob file + text content: stays blob" "$(mode_of "$T_TMP/keep.enc")" "blob"
enc --mode lines -i "$I/text" -o "$T_TMP/keep.enc"
t_eq "an explicit --mode wins over the existing file" "$(mode_of "$T_TMP/keep.enc")" "lines"

# ---- stdin, the library function, --seal -----------------------------------------------
t_eq "stdin: text -> lines" "$(printf 'hello\n' | enc --mode auto | head -n 1 | cut -d ' ' -f 2)" "lines"
t_eq "stdin: binary -> blob" "$(printf 'hel\000lo\n' | enc --mode auto | head -n 1 | cut -d ' ' -f 2)" "blob"
# ssenc_* functions read stdin; calling them without -i is intended
# shellcheck disable=SC2119
t_eq "library function: binary -> blob" "$(printf '\377' | ssenc_encrypt --mode auto --kdf "$T_KDF" | head -n 1 | cut -d ' ' -f 2)" "blob"
enc --mode auto --seal -i "$I/text" -o "$T_TMP/sealed.enc" --fresh
t_eq "--mode auto --seal on text: sealed lines file" "$(sed -n 3p "$T_TMP/sealed.enc" | cut -d ' ' -f 1)" "#seal"
t_code "--mode auto --seal on binary -> USAGE" 1 "$T_SSENC" encrypt --mode auto --seal -i "$I/binary"
t_code "--mode auto given to decrypt -> USAGE" 1 "$T_SSENC" decrypt --mode auto -i "$T_TMP/sealed.enc"

t_done
