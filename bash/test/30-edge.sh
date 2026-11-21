#!/usr/bin/env bash
# Round trips and edge cases: line splitting, whitespace, padding, blob chunking,
# deterministic re-encryption, rekey, tampering, exit codes, CLI behaviour.
# shellcheck source=helpers.bash
source "$(dirname "${BASH_SOURCE[0]}")/helpers.bash"

export SSENC_PASSWORD="edge case password"
enc() { "$T_SSENC" encrypt --kdf "$T_KDF" "$@"; }
dec() { "$T_SSENC" decrypt "$@"; }
compare() { if cmp -s "$1" "$2"; then echo same; else echo differs; fi; }
I="$T_TMP/in"
mkdir "$I"

# ---- inputs ---------------------------------------------------------------------------
: >"$I/empty"
printf 'a' >"$I/one-char-no-newline"
printf '\n' >"$I/single-newline"
printf '\n\n\nx\n\n' >"$I/empty-lines"
printf 'first\r\nsecond\r\n\r\n  third  \r\nlast-no-terminator' >"$I/crlf"
printf 'lone\rcarriage\r\nreturn\r' >"$I/lone-cr"
printf '   \n\t\n \t \t\n  x\n\tx\t\n x x \n    ' >"$I/whitespace"
printf 'key: value\n  indented: 1\n\t\ttabs: 2\n \t mixed: 3  \t \ntrailing:   \n' >"$I/config"
printf 'nul\000in\000line\n\000\n\000\000 \n \000 \nend\000' >"$I/nul"
printf 'bad utf8 \377\376\n\300\257 x\n\355\240\200\n caf\303\251 \342\234\223\n' >"$I/utf8"
printf '#ssenc1 lines ws=1 pad=16\n#slot pw argon2id m=64,t=1,p=1 AAAA BBBB\n#seal xyz\n#slot \n  #seal \n' >"$I/header-like"
printf 'same\nsame\nother\nsame\n  same  \n' >"$I/duplicates"
{
  printf '123456789012345\n1234567890123456\n12345678901234567\n'
  head -c 300 /dev/zero | tr '\0' 'q'
  printf '\n'
} >"$I/block-edges"
i=0
while ((i < 256)); do
  # shellcheck disable=SC2059
  printf "\\x$(printf '%02x' "$i")"
  i=$((i + 1))
done >"$I/all-bytes"
head -c 65536 /dev/zero | tr '\0' 'L' >"$I/line-64k"
printf '\nafter the long line\n' >>"$I/line-64k"

# ---- round trips ----------------------------------------------------------------------
roundtrip() { # LABEL FILE ENCRYPT-OPTIONS...
  local label=$1 file=$2
  shift 2
  if enc --fresh "$@" -i "$file" -o "$T_TMP/rt.enc" 2>"$T_TMP/rt.err" &&
    dec -i "$T_TMP/rt.enc" -o "$T_TMP/rt.dec" 2>>"$T_TMP/rt.err" &&
    cmp -s "$T_TMP/rt.dec" "$file"; then
    # the encrypted text must be 7-bit and free of NUL bytes whatever went in... except
    # for bytes kept in clear, which are only SP, TAB, CR, LF
    if [[ $(tr -d 'A-Za-z0-9_\n\r\t #=,:+/-' <"$T_TMP/rt.enc" | wc -c) -eq 0 ]]; then
      t_ok "round trip $label: $(basename "$file")"
    else
      t_fail "round trip $label: $(basename "$file")" "unexpected bytes in the encrypted text"
    fi
  else
    t_fail "round trip $label: $(basename "$file")" "$(head -n 1 "$T_TMP/rt.err")"
  fi
}

for f in "$I"/*; do
  [[ $(basename "$f") == line-64k ]] && continue
  roundtrip "lines default" "$f"
  roundtrip "lines ws=0 pad=0" "$f" --no-preserve-ws --pad 0
  roundtrip "lines pad=1 seal" "$f" --pad 1 --seal
  roundtrip "blob chunk=7" "$f" --mode blob --chunk 7
done
roundtrip "lines pad=4096" "$I/config" --pad 4096
roundtrip "lines ws=0 pad=5 seal" "$I/whitespace" --no-preserve-ws --pad 5 --seal
roundtrip "lines default" "$I/line-64k"
roundtrip "blob default" "$I/all-bytes" --mode blob
roundtrip "blob default" "$I/empty" --mode blob
roundtrip "blob chunk=1" "$I/crlf" --mode blob --chunk 1
roundtrip "blob chunk=256 (exact multiple)" "$I/all-bytes" --mode blob --chunk 256
roundtrip "blob chunk=255" "$I/all-bytes" --mode blob --chunk 255
roundtrip "blob chunk=4096 (streamed)" "$I/line-64k" --mode blob --chunk 4096
roundtrip "blob chunk=65536 (streamed, exact + rest)" "$I/line-64k" --mode blob

# ---- shape of the encrypted text ------------------------------------------------------
body() { sed -e '/^#ssenc1 /d' -e '/^#slot /d' -e '/^#seal /d' "$1"; }

enc -i "$I/whitespace" -o "$T_TMP/ws.enc"
body "$T_TMP/ws.enc" >"$T_TMP/ws.body"
tab=$'\t'
tk='[A-Za-z0-9_-]{43}'; re="^    ${tab}  ${tab} ${tab}   ${tk} ${tab}${tk}${tab}  ${tk}      \$"
got=$(tr '\n' ' ' <"$T_TMP/ws.body")
if [[ $got =~ $re ]]; then
  t_ok "ws=1: whitespace-only lines and leading/trailing whitespace stay in clear"
else
  t_fail "ws=1: whitespace-only lines and leading/trailing whitespace stay in clear" "$(xxd -p "$T_TMP/ws.body" | head -n 3)"
fi
t_eq "ws=1: no LF is added when the input has no final terminator" "$(tail -c 1 "$T_TMP/ws.enc" | xxd -p)" "20"

enc --no-preserve-ws --pad 0 -i "$I/whitespace" -o "$T_TMP/ws0.enc"
body "$T_TMP/ws0.enc" >"$T_TMP/ws0.body"
t_eq "ws=0: every line is a token, no whitespace left" "$(tr -d 'A-Za-z0-9_\n-' <"$T_TMP/ws0.body" | wc -c | tr -d ' ')" "0"
t_eq "ws=0: line count is kept" "$(wc -l <"$T_TMP/ws0.body" | tr -d ' ')" "6"

enc --no-preserve-ws --pad 0 -i "$I/empty-lines" -o "$T_TMP/el0.enc"
t_eq "ws=0 pad=0: an empty line becomes a 22-character token" "$(body "$T_TMP/el0.enc" | head -n 1 | tr -d '\n' | wc -c | tr -d ' ')" "22"
enc -i "$I/empty-lines" -o "$T_TMP/el1.enc"
t_eq "ws=1: empty lines stay empty" "$(body "$T_TMP/el1.enc" | sed -n '1p;2p;3p;5p' | tr -d '\n' | wc -c | tr -d ' ')" "0"

enc -i "$I/crlf" -o "$T_TMP/crlf.enc"
t_eq "CRLF terminators are kept in clear" "$(body "$T_TMP/crlf.enc" | tr -d -c '\r' | wc -c | tr -d ' ')" "4"
t_eq "header lines always end with LF only" "$(head -n 2 "$T_TMP/crlf.enc" | tr -d -c '\r' | wc -c | tr -d ' ')" "0"

linelen() { body "$1" | sed -n "${2}p" | tr -d '\n' | wc -c | tr -d ' '; }
enc -i "$I/block-edges" -o "$T_TMP/be.enc"
t_eq "pad=16: 15 bytes -> 32-byte record (43 chars)" "$(linelen "$T_TMP/be.enc" 1)" "43"
t_eq "pad=16: 16 bytes -> 48-byte record (64 chars)" "$(linelen "$T_TMP/be.enc" 2)" "64"
t_eq "pad=16: 17 bytes -> 48-byte record (64 chars)" "$(linelen "$T_TMP/be.enc" 3)" "64"
enc --pad 0 -i "$I/block-edges" -o "$T_TMP/be0.enc"
t_eq "pad=0: 15 bytes -> 31-byte record (42 chars)" "$(linelen "$T_TMP/be0.enc" 1)" "42"
enc --pad 1 -i "$I/block-edges" -o "$T_TMP/be1.enc"
t_eq "pad=1: 15 bytes -> 32-byte record (43 chars)" "$(linelen "$T_TMP/be1.enc" 1)" "43"
t_eq "pad=1: 16 bytes -> 33-byte record (44 chars)" "$(linelen "$T_TMP/be1.enc" 2)" "44"

enc -i "$I/duplicates" -o "$T_TMP/dup.enc"
body "$T_TMP/dup.enc" >"$T_TMP/dup.body"
l1=$(sed -n 1p "$T_TMP/dup.body")
t_eq "equal lines give equal tokens" "$(sed -n 2p "$T_TMP/dup.body")|$(sed -n 4p "$T_TMP/dup.body")|$(sed -n 5p "$T_TMP/dup.body")" "$l1|$l1|  $l1  "
t_eq "different lines give different tokens" "$(compare <(sed -n 3p "$T_TMP/dup.body") <(printf '%s\n' "$l1"))" "differs"

enc --mode blob --chunk 7 -i "$I/all-bytes" -o "$T_TMP/blob.enc"
t_eq "blob: body lines are 76 characters" "$(body "$T_TMP/blob.enc" | sed -n 1p | tr -d '\n' | wc -c | tr -d ' ')" "76"
t_eq "blob: body ends with LF" "$(tail -c 1 "$T_TMP/blob.enc" | xxd -p)" "0a"
# 256 bytes in 37 chunks -> 256 + 37*16 = 848 bytes -> 1131 characters -> 15 lines
t_eq "blob: body size" "$(body "$T_TMP/blob.enc" | wc -c | tr -d ' ')" "$((1131 + 15))"
"$T_SSENC" encrypt --kdf "$T_KDF" --mode blob -i "$I/empty" -o "$T_TMP/blob0.enc"
t_eq "blob: empty input is one empty chunk (22 characters)" "$(body "$T_TMP/blob0.enc" | tr -d '\n' | wc -c | tr -d ' ')" "22"

# ---- deterministic re-encryption ------------------------------------------------------
enc -i "$I/config" -o "$T_TMP/v1.enc"
sed -e 's/indented: 1/indented: 2/' "$I/config" >"$T_TMP/config2"
"$T_SSENC" encrypt --previous "$T_TMP/v1.enc" -i "$T_TMP/config2" -o "$T_TMP/v2.enc"
t_eq "--previous: only the changed line differs" "$(cmp -l "$T_TMP/v1.enc" "$T_TMP/v2.enc" | wc -l | tr -d ' ' | sed 's/^0$/none/')|$(diff "$T_TMP/v1.enc" "$T_TMP/v2.enc" | grep -c '^<')" "$(cmp -l "$T_TMP/v1.enc" "$T_TMP/v2.enc" | wc -l | tr -d ' ')|1"
"$T_SSENC" encrypt --previous "$T_TMP/v1.enc" -i "$I/config" -o "$T_TMP/v1b.enc"
t_same "--previous: unchanged input gives the identical file" "$T_TMP/v1b.enc" "$T_TMP/v1.enc"
enc -i "$I/config" -o "$T_TMP/v1c.enc"
t_eq "without --previous a new data key is used" "$(compare "$T_TMP/v1.enc" "$T_TMP/v1c.enc")" "differs"
cp "$T_TMP/v1.enc" "$T_TMP/auto.enc"
"$T_SSENC" encrypt -i "$T_TMP/config2" -o "$T_TMP/auto.enc"
t_same "-o on an existing ssenc1 file behaves like --previous" "$T_TMP/auto.enc" "$T_TMP/v2.enc"
cp "$T_TMP/v1.enc" "$T_TMP/fresh.enc"
enc --fresh -i "$I/config" -o "$T_TMP/fresh.enc"
t_eq "--fresh ignores the existing output file" "$(compare "$T_TMP/v1.enc" "$T_TMP/fresh.enc")" "differs"
cp "$T_TMP/v1.enc" "$T_TMP/keep.enc"
SSENC_PASSWORD=other t_code "existing output file with another password -> AUTH" 2 "$T_SSENC" encrypt -i "$I/config" -o "$T_TMP/keep.enc"
t_same "... and the existing file is left untouched" "$T_TMP/keep.enc" "$T_TMP/v1.enc"
"$T_SSENC" encrypt --previous "$T_TMP/v1.enc" --pad 0 --seal -i "$I/config" -o "$T_TMP/v3.enc"
t_eq "--previous: explicit options win, slots are copied" "$(head -n 1 "$T_TMP/v3.enc")|$(sed -n 2p "$T_TMP/v3.enc")|$(sed -n 3p "$T_TMP/v3.enc" | cut -c1-6)" "#ssenc1 lines ws=1 pad=0|$(sed -n 2p "$T_TMP/v1.enc")|#seal "
enc --no-preserve-ws --pad 3 --seal -i "$I/config" -o "$T_TMP/p1.enc"
"$T_SSENC" encrypt --previous "$T_TMP/p1.enc" -i "$I/config" -o "$T_TMP/p2.enc"
t_same "--previous: ws, pad and seal are inherited" "$T_TMP/p2.enc" "$T_TMP/p1.enc"

# in place: -i and -o name the same file
cp "$I/config" "$T_TMP/inplace"
enc -i "$T_TMP/inplace" -o "$T_TMP/inplace"
t_eq "in place encrypt" "$(head -c 8 "$T_TMP/inplace")" "#ssenc1 "
dec -i "$T_TMP/inplace" -o "$T_TMP/inplace"
t_same "in place decrypt" "$T_TMP/inplace" "$I/config"

# ---- rekey ----------------------------------------------------------------------------
for mode in lines blob; do
  if [[ $mode == lines ]]; then
    enc --pad 4 --seal -i "$I/config" -o "$T_TMP/rk.enc"
  else
    enc --mode blob --chunk 50 -i "$I/config" -o "$T_TMP/rk.enc"
  fi
  SSENC_NEW_PASSWORD=new1 "$T_SSENC" rekey --kdf "$T_KDF" --rewrap-only -i "$T_TMP/rk.enc" -o "$T_TMP/rk1.enc"
  t_eq "rekey --rewrap-only ($mode): everything but the slot line is unchanged" \
    "$(diff "$T_TMP/rk.enc" "$T_TMP/rk1.enc" | grep -c '^[<>]')|$(diff "$T_TMP/rk.enc" "$T_TMP/rk1.enc" | grep -c '^< #slot ')" "2|1"
  SSENC_PASSWORD=new1 dec -i "$T_TMP/rk1.enc" -o "$T_TMP/rk1.dec"
  t_same "rekey --rewrap-only ($mode): new password opens it" "$T_TMP/rk1.dec" "$I/config"
  t_code "rekey --rewrap-only ($mode): old password no longer works" 2 "$T_SSENC" decrypt -i "$T_TMP/rk1.enc"
  SSENC_NEW_PASSWORD=new2 "$T_SSENC" rekey --kdf "$T_KDF" -i "$T_TMP/rk.enc" -o "$T_TMP/rk2.enc"
  t_eq "rekey ($mode): header options are kept" "$(head -n 1 "$T_TMP/rk2.enc")|$(grep -c '^#seal ' "$T_TMP/rk2.enc")" "$(head -n 1 "$T_TMP/rk.enc")|$(grep -c '^#seal ' "$T_TMP/rk.enc")"
  t_eq "rekey ($mode): the body is encrypted under a new data key" "$(compare <(body "$T_TMP/rk.enc") <(body "$T_TMP/rk2.enc"))" "differs"
  SSENC_PASSWORD=new2 dec -i "$T_TMP/rk2.enc" -o "$T_TMP/rk2.dec"
  t_same "rekey ($mode): new password opens it" "$T_TMP/rk2.dec" "$I/config"
  SSENC_PASSWORD=wrong SSENC_NEW_PASSWORD=x t_code "rekey ($mode): wrong old password -> AUTH" 2 "$T_SSENC" rekey --kdf "$T_KDF" -i "$T_TMP/rk.enc"
done
t_code "rekey: no new key -> USAGE" 1 "$T_SSENC" rekey -i "$T_TMP/rk.enc"
printf 'file-pw\r\n' >"$T_TMP/pwfile-crlf"
printf 'file-pw' >"$T_TMP/pwfile-bare"
printf 'file-pw\n' >"$T_TMP/pwfile-lf"
"$T_SSENC" rekey --kdf "$T_KDF" --new-password-file "$T_TMP/pwfile-crlf" -i "$T_TMP/rk.enc" -o "$T_TMP/rk3.enc"
env -u SSENC_PASSWORD "$T_SSENC" decrypt --password-file "$T_TMP/pwfile-bare" -i "$T_TMP/rk3.enc" -o "$T_TMP/rk3.dec"
t_same "password file: one trailing CRLF is not part of the password" "$T_TMP/rk3.dec" "$I/config"
SSENC_PASSWORD=ignored "$T_SSENC" decrypt --password-file "$T_TMP/pwfile-lf" -i "$T_TMP/rk3.enc" -o "$T_TMP/rk3b.dec"
t_same "password file: wins over SSENC_PASSWORD, trailing LF stripped" "$T_TMP/rk3b.dec" "$I/config"

# ---- tampering and malformed input ----------------------------------------------------
enc -i "$I/config" -o "$T_TMP/t.enc"
swap_lines() { sed -e "$2{h;d;}" -e "$3G" "$1"; } # moves line $2 behind line $3
tamper_char() { # FILE LINE -> flips the first character of that line between A and B
  sed -e "$2s/^\\([ ${tab}]*\\)A/\\1@/" -e "$2s/^\\([ ${tab}]*\\)[^ ${tab}@]/\\1A/" -e "$2s/^\\([ ${tab}]*\\)@/\\1B/" "$1"
}
tamper_char "$T_TMP/t.enc" 3 >"$T_TMP/t1.enc"
t_code "modified line token -> AUTH" 2 "$T_SSENC" decrypt -i "$T_TMP/t1.enc"
sed -e '3s/$/!/' "$T_TMP/t.enc" >"$T_TMP/t2.enc"
t_code "line that is not base64url -> MALFORMED" 3 "$T_SSENC" decrypt -i "$T_TMP/t2.enc"
sed -e '3s/.*/AAAAAAAAAAAAAAAAAAAA/' "$T_TMP/t.enc" >"$T_TMP/t3.enc"
t_code "line shorter than a tag -> MALFORMED" 3 "$T_SSENC" decrypt -i "$T_TMP/t3.enc"
sed -e '3s/$/AA/' "$T_TMP/t.enc" >"$T_TMP/t4.enc"
t_code "line with an impossible base64 length -> MALFORMED" 3 "$T_SSENC" decrypt -i "$T_TMP/t4.enc"
swap_lines "$T_TMP/t.enc" 3 4 >"$T_TMP/t5.enc"
dec -i "$T_TMP/t5.enc" -o "$T_TMP/t5.dec"
t_eq "without a seal, reordered lines still decrypt (documented property)" "$(sed -n 1p "$T_TMP/t5.dec")|$(sed -n 2p "$T_TMP/t5.dec")" "$(sed -n 2p "$I/config")|$(sed -n 1p "$I/config")"

enc --seal -i "$I/config" -o "$T_TMP/s.enc"
swap_lines "$T_TMP/s.enc" 4 5 >"$T_TMP/s1.enc"
t_code "seal: reordered lines -> AUTH" 2 "$T_SSENC" decrypt -i "$T_TMP/s1.enc"
sed -e '5d' "$T_TMP/s.enc" >"$T_TMP/s2.enc"
t_code "seal: removed line -> AUTH" 2 "$T_SSENC" decrypt -i "$T_TMP/s2.enc"
sed -e '1s/pad=16/pad=32/' "$T_TMP/s.enc" >"$T_TMP/s3.enc"
t_code "seal: modified header line -> AUTH" 2 "$T_SSENC" decrypt -i "$T_TMP/s3.enc"
sed -e '3s/#seal ./#seal !/' "$T_TMP/s.enc" >"$T_TMP/s4.enc"
t_code "seal: invalid seal line -> MALFORMED" 3 "$T_SSENC" decrypt -i "$T_TMP/s4.enc"

enc --pad 0 -i "$I/config" -o "$T_TMP/p0.enc"
sed -e '1s/pad=0/pad=16/' "$T_TMP/p0.enc" >"$T_TMP/p0b.enc"
t_code "invalid line padding -> MALFORMED" 3 "$T_SSENC" decrypt -i "$T_TMP/p0b.enc"

enc --mode blob --chunk 16 -i "$I/all-bytes" -o "$T_TMP/b.enc"
{
  head -n 2 "$T_TMP/b.enc"
  body "$T_TMP/b.enc" | sed -e '$d'
} >"$T_TMP/b1.enc"
t_code "blob: truncated inside a tag -> MALFORMED" 3 "$T_SSENC" decrypt -i "$T_TMP/b1.enc"
{
  head -n 2 "$T_TMP/b.enc"
  body "$T_TMP/b.enc" | tr -d '\n' | head -c 368
} >"$T_TMP/b2.enc"
t_code "blob: truncated inside a record -> AUTH" 2 "$T_SSENC" decrypt -i "$T_TMP/b2.enc"
{
  head -n 2 "$T_TMP/b.enc"
  body "$T_TMP/b.enc" | tr -d '\n' | head -c $((32 * 4 * 3 / 3))
} >"$T_TMP/b3.enc"
t_code "blob: truncated at a record boundary -> AUTH" 2 "$T_SSENC" decrypt -i "$T_TMP/b3.enc"
tamper_char "$T_TMP/b.enc" 4 >"$T_TMP/b4.enc"
t_code "blob: modified body -> AUTH" 2 "$T_SSENC" decrypt -i "$T_TMP/b4.enc"
sed -e '3s/^./!/' "$T_TMP/b.enc" >"$T_TMP/b5.enc"
t_code "blob: body that is not base64url -> MALFORMED" 3 "$T_SSENC" decrypt -i "$T_TMP/b5.enc"
head -n 2 "$T_TMP/b.enc" >"$T_TMP/b6.enc"
t_code "blob: empty body -> MALFORMED" 3 "$T_SSENC" decrypt -i "$T_TMP/b6.enc"
{
  head -n 2 "$T_TMP/b.enc"
  printf 'AAAAAAAAAAAAAAAAAAAA\n'
} >"$T_TMP/b7.enc"
t_code "blob: record shorter than a tag -> MALFORMED" 3 "$T_SSENC" decrypt -i "$T_TMP/b7.enc"
{
  head -n 2 "$T_TMP/b.enc" | sed -e "s/\$/$(printf '\r')/"
  body "$T_TMP/b.enc" | sed -e "s/\$/$(printf '\r')/" -e 's/^\(.\{10\}\)/\1 	/'
} >"$T_TMP/b8.enc"
dec -i "$T_TMP/b8.enc" -o "$T_TMP/b8.dec" 2>"$T_TMP/err"
t_same "blob: CRLF line ends and blanks in the body are ignored" "$T_TMP/b8.dec" "$I/all-bytes"
enc --mode blob --chunk 4096 -i "$I/line-64k" -o "$T_TMP/bs.enc"
{
  head -n 2 "$T_TMP/bs.enc"
  body "$T_TMP/bs.enc" | sed -e '$d'
} >"$T_TMP/bs1.enc"
t_code "blob (streamed): truncated -> AUTH" 2 "$T_SSENC" decrypt -i "$T_TMP/bs1.enc"
tamper_char "$T_TMP/bs.enc" 40 >"$T_TMP/bs2.enc"
t_code "blob (streamed): modified body -> AUTH" 2 "$T_SSENC" decrypt -i "$T_TMP/bs2.enc"

slot=$(sed -n 2p "$T_TMP/t.enc")
mal() { # NAME then the file content on stdin
  cat >"$T_TMP/mal.enc"
  t_code "$1 -> MALFORMED" 3 "$T_SSENC" decrypt -i "$T_TMP/mal.enc"
  t_code "$1 -> MALFORMED (inspect)" 3 "$T_SSENC" inspect -i "$T_TMP/mal.enc"
}
mal "empty input" </dev/null
mal "plain text" < <(printf 'hello world\n')
mal "random bytes" < <(head -c 3000 /dev/urandom)
mal "other format version" < <(printf '#ssenc2 lines ws=1 pad=16\n%s\nAAAA\n' "$slot")
mal "no slot line" < <(printf '#ssenc1 lines ws=1 pad=16\nAAAA\n')
mal "ws out of range" < <(printf '#ssenc1 lines ws=2 pad=16\n%s\n' "$slot")
mal "pad out of range" < <(printf '#ssenc1 lines ws=1 pad=4097\n%s\n' "$slot")
mal "number with a leading zero" < <(printf '#ssenc1 lines ws=1 pad=016\n%s\n' "$slot")
mal "two spaces between fields" < <(printf '#ssenc1 lines ws=1  pad=16\n%s\n' "$slot")
mal "chunk zero" < <(printf '#ssenc1 blob chunk=0\n%s\n' "$slot")
mal "chunk out of range" < <(printf '#ssenc1 blob chunk=1048577\n%s\n' "$slot")
mal "seal line in blob mode" < <(printf '#ssenc1 blob chunk=64\n%s\n#seal %s\n' "$slot" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
mal "argon2id m below 8*p" < <(printf '#ssenc1 lines ws=1 pad=16\n%s\n' "${slot/m=64,t=1,p=1/m=7,t=1,p=1}")
mal "argon2id t out of range" < <(printf '#ssenc1 lines ws=1 pad=16\n%s\n' "${slot/m=64,t=1,p=1/m=64,t=65,p=1}")
mal "argon2id m out of range" < <(printf '#ssenc1 lines ws=1 pad=16\n%s\n' "${slot/m=64,t=1,p=1/m=4194305,t=1,p=1}")
mal "wrapped key of the wrong length" < <(printf '#ssenc1 lines ws=1 pad=16\n%sAAAA\n' "$slot")
mal "unknown slot type" < <(printf '#ssenc1 lines ws=1 pad=16\n#slot pgp x y\n')
mal "ssh slot of an unsupported key type" < <(printf '#ssenc1 lines ws=1 pad=16\n#slot ssh ecdsa-sha2-nistp256 SHA256:%s %s %s\n' "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
mal "NUL byte in the header line" < <(printf '#ssenc1 lines ws=1 pad=16\000\n%s\n' "$slot")

{
  sed -n '1,2p' "$T_TMP/t.enc" | sed -e "s/\$/$(printf '\r')/"
  body "$T_TMP/t.enc"
} >"$T_TMP/crlfhdr.enc"
dec -i "$T_TMP/crlfhdr.enc" -o "$T_TMP/crlfhdr.dec" 2>"$T_TMP/err"
t_same "header lines ending in CRLF are accepted" "$T_TMP/crlfhdr.dec" "$I/config"
printf '%s\n%s' "$(sed -n 1p "$T_TMP/t.enc")" "$slot" >"$T_TMP/nobody.enc"
t_eq "header without a final LF and without a body decrypts to nothing" "$(dec -i "$T_TMP/nobody.enc" | wc -c | tr -d ' ')" "0"

# ---- command line ---------------------------------------------------------------------
t_eq "--version" "$("$T_SSENC" --version)" "ssenc bash 0.1.0"
t_eq "--help goes to stdout and succeeds" "$("$T_SSENC" --help | head -n 1)" "usage:"
usage() {
  local name=$1
  shift
  t_code "$name -> USAGE" 1 "$T_SSENC" "$@"
}
usage "unknown command" frobnicate
usage "unknown option" encrypt --frob -i "$I/config"
usage "option without its value" encrypt -i
usage "--pad not a number" encrypt --pad x -i "$I/config"
usage "--pad negative" encrypt --pad -1 -i "$I/config"
usage "--pad out of range" encrypt --pad 4097 -i "$I/config"
usage "--chunk zero" encrypt --mode blob --chunk 0 -i "$I/config"
usage "--chunk out of range" encrypt --mode blob --chunk 1048577 -i "$I/config"
usage "--chunk absurdly large" encrypt --mode blob --chunk 99999999999999999999999 -i "$I/config"
usage "--mode unknown" encrypt --mode stream -i "$I/config"
usage "--seal in blob mode" encrypt --mode blob --seal -i "$I/config"
usage "--kdf unknown profile" encrypt --kdf fast -i "$I/config"
usage "--kdf out of range" encrypt --kdf m=4,t=1,p=1 -i "$I/config"
usage "--previous with --fresh" encrypt --previous "$T_TMP/t.enc" --fresh -i "$I/config"
usage "--previous unreadable" encrypt --previous "$T_TMP/does-not-exist" -i "$I/config"
usage "input unreadable" encrypt -i "$T_TMP/does-not-exist"
usage "password file unreadable" decrypt --password-file "$T_TMP/does-not-exist" -i "$T_TMP/t.enc"
usage "ssh key file unreadable" decrypt --ssh-key "$T_TMP/does-not-exist" -i "$T_TMP/t.enc"
usage "encrypt option given to decrypt" decrypt --pad 4 -i "$T_TMP/t.enc"
usage "-o given to inspect" inspect -i "$T_TMP/t.enc" -o "$T_TMP/x"
usage "rekey option given to encrypt" encrypt --rewrap-only -i "$I/config"
usage "two --ssh-key for decrypt" decrypt --ssh-key SHA256:a --ssh-key SHA256:b -i "$T_TMP/t.enc"
SSENC_PASSWORD='' usage "empty password" encrypt -i "$I/config"
: >"$T_TMP/pwfile-empty"
usage "empty password file" encrypt --password-file "$T_TMP/pwfile-empty" -i "$I/config"
SSENC_NEW_PASSWORD='' usage "empty new password" rekey -i "$T_TMP/t.enc"
t_code "no key at all -> USAGE" 1 env -u SSENC_PASSWORD "$T_SSENC" encrypt -i "$I/config" </dev/null
t_code "--previous that is not an ssenc1 file -> MALFORMED" 3 "$T_SSENC" encrypt --previous "$I/config" -i "$I/config"
SSENC_PASSWORD=other t_code "--previous with another password -> AUTH" 2 "$T_SSENC" encrypt --previous "$T_TMP/t.enc" -i "$I/config"

# stdin -> stdout, and the library functions keep the caller's shell untouched
t_eq "stdin to stdout" "$(printf 'pipe me\n' | enc | dec)" "pipe me"
before="$(set +o | sort)|$IFS|$(umask)"
out=$(printf '  lib\n' | ssenc_encrypt --kdf "$T_KDF" | ssenc_decrypt)
t_eq "library functions: stdin to stdout" "$out" "  lib"
ssenc_decrypt <"$I/config" >/dev/null 2>&1
t_eq "library functions: return the exit code" "$?" "3"
t_eq "library functions: caller's options, IFS and umask unchanged" "$(set +o | sort)|$IFS|$(umask)" "$before"

t_done
