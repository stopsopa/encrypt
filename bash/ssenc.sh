#!/usr/bin/env bash
# shellcheck disable=SC2059
# (SC2059: this file deliberately passes generated '\xHH' strings as printf formats;
#  that is how binary data is written without ever holding it in a shell variable.)
#
# ssenc - Bash implementation of the ssenc1 format (see ../SPEC.md).
#
# Sourceable library. Public functions (stdin -> stdout unless -i / -o is given; the
# options are the long flags of the CLI, SPEC.md section 7):
#
#     ssenc_encrypt  [--mode lines|blob|auto] [--no-preserve-ws] [--pad N] [--chunk N]
#                    [--kdf PROFILE] [--seal] [--previous FILE | --fresh]
#                    [--password-file F] [--ssh-key X]... [-i IN] [-o OUT]
#     ssenc_decrypt  [--password-file F | --ssh-key X] [-i IN] [-o OUT]
#     ssenc_rekey    [--password-file F | --ssh-key X] [--new-password-file F]
#                    [--new-ssh-key X]... [--kdf PROFILE] [--rewrap-only] [-i IN] [-o OUT]
#     ssenc_inspect  [-i IN]
#     ssenc_cli      ARGV...            the whole command line (bin/ssenc calls this)
#
# Passwords come from --password-file / --new-password-file or from the environment
# variables SSENC_PASSWORD / SSENC_NEW_PASSWORD. Return codes: 0 ok, 1 USAGE, 2 AUTH,
# 3 MALFORMED, 4 ENV; errors go to stderr as "ssenc: <KIND>: <message>" and nothing is
# written to the output on error.
#
# Primitives, for unit tests (all values are lowercase hex, result on stdout):
#
#     ssenc_hkdf32      IKM SALT INFO          SALT "" means 32 zero bytes; INFO is text
#     ssenc_sivkey      PARENT PURPOSE         prints "<kmac> <kenc>"
#     ssenc_siv_encrypt KMAC KENC AD PT
#     ssenc_siv_decrypt KMAC KENC AD INPUT     returns 2 (AUTH) / 3 (MALFORMED)
#     ssenc_argon2id    PASSWORD SALT M T P
#
# Every public function runs in a subshell, so sourcing this file changes neither shell
# options nor variables of the caller (apart from defining functions and SSENC_VERSION).
#
# Requirements: bash >= 4.0, OpenSSL >= 3.2 as `openssl` (LibreSSL is not enough: no
# Argon2id), ssh-keygen / ssh-add from OpenSSH >= 8.1 (only for ssh keys), xxd, base64 and
# POSIX tr, sed, head, tail, wc, cat, fold, split, mktemp. Run ./envverify.sh to check.
#
# How it works
#   Binary data is never stored in a shell variable. It lives in files of a private
#   temporary directory (mktemp -d, umask 077, removed on exit) or, inside the shell, as
#   hex ("6869") or as printf escapes ("\x68\x69").
#   Process start-up dominates the cost, so lines mode does not call openssl per line:
#   all HMACs of a file are computed by `openssl dgst` reading many small files at once,
#   and the AES-256-CTR keystream of all lines comes from a single `openssl enc
#   -aes-256-ecb` over the counter blocks; the XOR happens in the shell. Blob mode with
#   chunks of 4096 bytes or more streams every chunk through `openssl dgst` and
#   `openssl enc -aes-256-ctr` instead (two openssl processes per chunk).
#
# Known limitations (inherent to "bash + openssl CLI", not bugs to fix here)
#   * Keys on the command line. `openssl` accepts raw keys only as arguments (-K,
#     -macopt hexkey:, -kdfopt hexpass:), so the password and the derived keys are visible
#     to other processes of the same machine (ps) while a command runs. Do not use this
#     implementation on a shared host; use the Rust or TypeScript one there.
#   * Tag comparison is a shell string comparison, not constant-time.
#   * Speed: fine for configuration and secret files, slow for megabytes of text.

SSENC_VERSION="0.1.0"

# ---------------------------------------------------------------------------------------
# errors, environment
# ---------------------------------------------------------------------------------------

# _ssenc_die KIND MESSAGE - only ever called inside the subshell of a public function.
_ssenc_die() {
  local code=70
  case $1 in
    USAGE) code=1 ;;
    AUTH) code=2 ;;
    MALFORMED) code=3 ;;
    ENV) code=4 ;;
  esac
  printf 'ssenc: %s: %s\n' "$1" "$2" >&2
  exit "$code"
}

_ssenc_usage_text() {
  cat <<'EOF'
usage:
  ssenc encrypt [--mode lines|blob|auto] [--no-preserve-ws] [--pad N] [--chunk N] [--kdf PROFILE]
                [--seal] [--previous FILE | --fresh] KEYS [-i IN] [-o OUT]
  ssenc decrypt KEY [-i IN] [-o OUT]
  ssenc rekey   KEY NEWKEYS [--kdf PROFILE] [--rewrap-only] [-i IN] [-o OUT]
  ssenc inspect [-i IN]
  ssenc --version

  KEY/KEYS  --password-file F | env SSENC_PASSWORD | --ssh-key PUBFILE_OR_FINGERPRINT
  NEWKEYS   --new-password-file F | env SSENC_NEW_PASSWORD | --new-ssh-key PUBFILE_OR_FINGERPRINT
EOF
}

_ssenc_usage() {
  _ssenc_die USAGE "$1
$(_ssenc_usage_text)"
}

# Sets up the subshell: predictable shell options, C locale, temp dir, lookup tables.
# The caller must have declared `local -A _SSENC_D` (bash 4.0 has no `declare -g`).
_ssenc_init() {
  set +e +u +f
  set +o pipefail
  shopt -u nocasematch nullglob failglob 2>/dev/null
  IFS=$' \t\n'
  export LC_ALL=C
  umask 077
  local tool
  for tool in openssl xxd; do
    command -v "$tool" >/dev/null 2>&1 || _ssenc_die ENV "required tool '$tool' not found in PATH"
  done
  _T=$(mktemp -d "${TMPDIR:-/tmp}/ssenc.XXXXXX" 2>/dev/null) || _ssenc_die ENV "cannot create a temporary directory"
  [[ -n $_T && -d $_T ]] || _ssenc_die ENV "cannot create a temporary directory"
  trap 'rm -rf "$_T"' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM HUP
  mkdir "$_T/m" || _ssenc_die ENV "cannot write to the temporary directory"

  local alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" i c
  _SSENC_A=()
  for ((i = 0; i < 64; i++)); do
    c=${alphabet:i:1}
    _SSENC_A[i]=$c
    _SSENC_D[$c]=$i
  done
  printf -v _SSENC_Z '%4096s' ''
  _SSENC_Z=${_SSENC_Z// /\\x00}
  _X00='\x00' _X09='\x09' _X0A='\x0a' _X0D='\x0d' _X20='\x20' _X80='\x80'
  _ZERO32=0000000000000000000000000000000000000000000000000000000000000000
  _AD_NONE='\x00\x00\x00\x00\x00\x00\x00\x00'
  _AD_SLOT='\x00\x00\x00\x00\x00\x00\x00\x0bssenc1/slot'
  _AG_LOADED=0
}

# Runs "$@" inside an initialised environment. Call only from a ( subshell ) function.
_ssenc_run() {
  local -A _SSENC_D
  _ssenc_init
  "$@"
}

_ssenc_size() {
  local n
  n=$(wc -c <"$1") || n=0
  _SIZE=$((n))
}

# ---------------------------------------------------------------------------------------
# hex / escape / base64 helpers (pure shell, results in globals)
# ---------------------------------------------------------------------------------------

# hex -> printf escapes, in _E. For short values (keys, tags, salts).
_ssenc_hex2esc() {
  local h=$1 i o=
  for ((i = 0; i < ${#h}; i += 2)); do o+="\\x${h:i:2}"; done
  _E=$o
}

_ssenc_ishex() {
  [[ -n $1 && $(( ${#1} % 2 )) -eq 0 && $1 != *[!0-9a-f]* ]]
}

# hex -> unpadded base64url, in _B64. (Long input is cut into pieces first: substring
# expansion costs time proportional to the length of the whole string.)
_ssenc_b64e() {
  local h=$1 n=${#1} off c m i v o=
  for ((off = 0; off < n; off += 960)); do
    c=${h:off:960}
    m=${#c}
    for ((i = 0; i + 6 <= m; i += 6)); do
      v=$((0x${c:i:6}))
      o+=${_SSENC_A[v >> 18]}${_SSENC_A[(v >> 12) & 63]}${_SSENC_A[(v >> 6) & 63]}${_SSENC_A[v & 63]}
    done
    case $((m - i)) in
      2)
        v=$((0x${c:i:2} << 16))
        o+=${_SSENC_A[v >> 18]}${_SSENC_A[(v >> 12) & 63]}
        ;;
      4)
        v=$((0x${c:i:4} << 8))
        o+=${_SSENC_A[v >> 18]}${_SSENC_A[(v >> 12) & 63]}${_SSENC_A[(v >> 6) & 63]}
        ;;
    esac
  done
  _B64=$o
}

# unpadded base64url -> hex in _HEX; returns 1 when the text is not valid. Like the
# reference, non-zero unused trailing bits are ignored and "" decodes to "".
_ssenc_b64d() {
  local t=$1 n=${#1} off c m i v x o=
  _HEX=
  [[ $t == *[!A-Za-z0-9_-]* ]] && return 1
  ((n % 4 == 1)) && return 1
  for ((off = 0; off < n; off += 640)); do
    c=${t:off:640}
    m=${#c}
    for ((i = 0; i + 4 <= m; i += 4)); do
      v=$(((${_SSENC_D[${c:i:1}]} << 18) | (${_SSENC_D[${c:i+1:1}]} << 12) | (${_SSENC_D[${c:i+2:1}]} << 6) | ${_SSENC_D[${c:i+3:1}]}))
      printf -v x '%06x' "$v"
      o+=$x
    done
    case $((m - i)) in
      2)
        v=$((((${_SSENC_D[${c:i:1}]} << 6) | ${_SSENC_D[${c:i+1:1}]}) >> 4))
        printf -v x '%02x' "$v"
        o+=$x
        ;;
      3)
        v=$((((${_SSENC_D[${c:i:1}]} << 12) | (${_SSENC_D[${c:i+1:1}]} << 6) | ${_SSENC_D[${c:i+2:1}]}) >> 2))
        printf -v x '%04x' "$v"
        o+=$x
        ;;
    esac
  done
  _HEX=$o
  return 0
}

# standard base64 (padded or not) -> hex in _HEX; returns 1 when invalid.
_ssenc_b64std_d() {
  local s=$1
  while [[ $s == *= ]]; do s=${s%=}; done
  s=${s//+/-}
  s=${s//\//_}
  _ssenc_b64d "$s"
}

# Binary stdin -> one text line per input line, every byte as \xHH, terminator included.
# The last output line has no newline (use: while IFS= read -r l || [[ -n $l ]]).
_ssenc_esclines() {
  xxd -p -c 1 | sed -e 's/^/\\x/' -e 's/^\\x0a$/&@/' | tr -d '\n' | tr '@' '\n'
}

# ---------------------------------------------------------------------------------------
# primitives (SPEC.md section 1)
# ---------------------------------------------------------------------------------------

# _ssenc_hmac_files KEYHEX FILE... -> _H[i] = HMAC-SHA-256 of file i (hex). One process.
_ssenc_hmac_files() {
  local key=$1 out i h
  shift
  _H=()
  mapfile -t out < <(openssl dgst -sha256 -mac HMAC -macopt "hexkey:$key" "$@" 2>/dev/null)
  ((${#out[@]} == $#)) || _ssenc_die ENV "openssl dgst (HMAC-SHA-256) failed; is 'openssl' OpenSSL >= 3.2? (run envverify.sh)"
  for ((i = 0; i < ${#out[@]}; i++)); do
    h=${out[i]##*= }
    [[ ${#h} -eq 64 && $h != *[!0-9a-f]* ]] || _ssenc_die ENV "unexpected output of openssl dgst"
    _H[i]=$h
  done
}

# _ssenc_hkdf IKMHEX SALTHEX INFO... -> _HK[i] = HKDF32(ikm, salt, INFO_i). Two processes.
_ssenc_hkdf() {
  local ikm=$1 salt=${2:-$_ZERO32} i files=()
  shift 2
  _ssenc_hex2esc "$ikm"
  printf -- "$_E" >"$_T/hk.ikm"
  _ssenc_hmac_files "$salt" "$_T/hk.ikm"
  local prk=${_H[0]}
  for ((i = 1; i <= $#; i++)); do
    printf '%s\001' "${!i}" >"$_T/hk.$i"
    files+=("$_T/hk.$i")
  done
  _ssenc_hmac_files "$prk" "${files[@]}"
  _HK=("${_H[@]}")
}

# _ssenc_sivkey PARENTHEX PURPOSE -> _KM, _KE
_ssenc_sivkey() {
  _ssenc_hkdf "$1" "" "ssenc1/$2-mac" "ssenc1/$2-enc"
  _KM=${_HK[0]}
  _KE=${_HK[1]}
}

# _ssenc_argon2 PWHEX SALTHEX M T P -> _KEK
_ssenc_argon2() {
  local out
  out=$(openssl kdf -keylen 32 -kdfopt "hexpass:$1" -kdfopt "hexsalt:$2" -kdfopt "iter:$4" \
    -kdfopt "memcost:$3" -kdfopt "lanes:$5" ARGON2ID 2>/dev/null)
  out=${out//:/}
  out=${out//[$' \t\r\n']/}
  out=${out,,}
  [[ ${#out} -eq 64 && $out != *[!0-9a-f]* ]] ||
    _ssenc_die ENV "openssl cannot compute Argon2id (m=$3,t=$4,p=$5); OpenSSL >= 3.2 is required (run envverify.sh)"
  _KEK=$out
}

_ssenc_rand() {
  local out
  out=$(openssl rand -hex "$1" 2>/dev/null)
  [[ ${#out} -eq $(($1 * 2)) && $out != *[!0-9a-f]* ]] || _ssenc_die ENV "openssl rand failed"
  _RAND=$out
}

# tag (32 hex) -> _IV: the tag with the top bit of bytes 8 and 12 cleared.
_ssenc_iv() {
  local t=$1 a b
  printf -v a '%02x' $((0x${t:16:2} & 0x7f))
  printf -v b '%02x' $((0x${t:24:2} & 0x7f))
  _IV=${t:0:16}$a${t:18:6}$b${t:26:6}
}

# Batched SIV. Items 0.._N-1; _ADP[i] = printf escapes of u64be(len(ad)) || ad,
# _LEN[i] = length of the plaintext / ciphertext in bytes.

# AES-256-CTR keystream blocks for all items (in item order) -> _KS[]. One openssl.
_ssenc_keystream() {
  local kenc=$1 i j nb total=0
  _KS=()
  for ((i = 0; i < _N; i++)); do total=$((total + (_LEN[i] + 15) / 16)); done
  ((total == 0)) && return 0
  mapfile -t _KS < <(
    for ((i = 0; i < _N; i++)); do
      nb=$(((_LEN[i] + 15) / 16))
      ((nb == 0)) && continue
      _ssenc_iv "${_TAG[i]}"
      hi=${_IV:0:16}
      # After the two bits are cleared the low half is below 2^63 and its low 32 bits
      # are below 2^31, so adding the block index can neither overflow nor carry.
      lo=$((0x${_IV:16:16}))
      for ((j = 0; j < nb; j++)); do printf '%s%016x\n' "$hi" $((lo + j)); done
    done | xxd -r -p | openssl enc -aes-256-ecb -nopad -K "$kenc" 2>/dev/null | xxd -p -c 16
  )
  ((${#_KS[@]} == total)) || _ssenc_die ENV "openssl enc (AES-256) failed; is 'openssl' OpenSSL >= 3.2? (run envverify.sh)"
}

# Substring expansion costs time proportional to the length of the whole string, so the
# loops below never index into a long string directly: they cut it into pieces of 480
# bytes first and work on those.

# XOR with the next keystream blocks (_KS from index _KSI), 32 bits at a time.
# _ssenc_xor_eh: data as printf escapes -> _X as hex      (encryption)
# _ssenc_xor_he: data as hex            -> _X as escapes  (decryption)
_ssenc_xor_eh() {
  local d=$1 n=${#1} off m i c p k o out=
  for ((off = 0; off < n; off += 1920)); do
    c=${d:off:1920}
    c=${c//\\x/}
    m=${#c}
    for ((i = 0; i < m; i += 32)); do
      p=${c:i:32}00000000000000000000000000000000
      k=${_KS[_KSI++]}
      printf -v o '%08x%08x%08x%08x' $((0x${p:0:8} ^ 0x${k:0:8})) $((0x${p:8:8} ^ 0x${k:8:8})) \
        $((0x${p:16:8} ^ 0x${k:16:8})) $((0x${p:24:8} ^ 0x${k:24:8}))
      out+=$o
    done
  done
  # the last block was zero-extended: n / 4 bytes = n / 2 hex digits are real
  _X=${out:0:n/2}
}

_ssenc_xor_he() {
  local d=$1 n=${#1} off m i c p k o out=
  for ((off = 0; off < n; off += 960)); do
    c=${d:off:960}
    m=${#c}
    for ((i = 0; i < m; i += 32)); do
      p=${c:i:32}00000000000000000000000000000000
      k=${_KS[_KSI++]}
      printf -v o '%08x%08x%08x%08x' $((0x${p:0:8} ^ 0x${k:0:8})) $((0x${p:8:8} ^ 0x${k:8:8})) \
        $((0x${p:16:8} ^ 0x${k:16:8})) $((0x${p:24:8} ^ 0x${k:24:8}))
      out+="\\x${o:0:2}\\x${o:2:2}\\x${o:4:2}\\x${o:6:2}\\x${o:8:2}\\x${o:10:2}\\x${o:12:2}\\x${o:14:2}\\x${o:16:2}\\x${o:18:2}\\x${o:20:2}\\x${o:22:2}\\x${o:24:2}\\x${o:26:2}\\x${o:28:2}\\x${o:30:2}"
    done
  done
  _X=${out:0:n*2}
}

# HMAC tags of all items: file i = _ADP[i] || <escapes in array named by $2>[i].
# -> _MAC[i] (first 16 bytes, hex).
_ssenc_tags() {
  local kmac=$1 src=$2 b i files ref
  _MAC=()
  for ((b = 0; b < _N; b += 256)); do
    files=()
    for ((i = b; i < _N && i < b + 256; i++)); do
      ref="${src}[$i]"
      printf -- "${_ADP[i]}${!ref}" >"$_T/m/$((i - b))" || _ssenc_die ENV "cannot write to the temporary directory"
      files+=("$_T/m/$((i - b))")
    done
    _ssenc_hmac_files "$kmac" "${files[@]}"
    for ((i = b; i < _N && i < b + 256; i++)); do _MAC[i]=${_H[i - b]:0:32}; done
  done
}

# in: _N, _ADP[], _PT[] (escapes)   out: _TAG[] (hex), _CT[] (hex)
_ssenc_siv_enc_batch() {
  local kmac=$1 kenc=$2 i
  _TAG=() _CT=() _LEN=()
  for ((i = 0; i < _N; i++)); do _LEN[i]=$((${#_PT[i]} / 4)); done
  _ssenc_tags "$kmac" _PT
  _TAG=("${_MAC[@]}")
  _ssenc_keystream "$kenc"
  _KSI=0
  for ((i = 0; i < _N; i++)); do
    _ssenc_xor_eh "${_PT[i]}"
    _CT[i]=$_X
  done
}

# in: _N, _ADP[], _TAG[] (hex), _CTH[] (hex)   out: _PT[] (escapes), _OK[] (1 = authentic)
_ssenc_siv_dec_batch() {
  local kmac=$1 kenc=$2 i
  _PT=() _OK=() _LEN=()
  for ((i = 0; i < _N; i++)); do _LEN[i]=$((${#_CTH[i]} / 2)); done
  _ssenc_keystream "$kenc"
  _KSI=0
  for ((i = 0; i < _N; i++)); do
    _ssenc_xor_he "${_CTH[i]}"
    _PT[i]=$_X
  done
  _ssenc_tags "$kmac" _PT
  for ((i = 0; i < _N; i++)); do
    if [[ ${_MAC[i]} == "${_TAG[i]}" ]]; then _OK[i]=1; else _OK[i]=0; fi
  done
}

# wrapped (96 hex) = SIV-Encrypt(wrap keys of KEK, "ssenc1/slot", DEK) -> _WRAPPED
_ssenc_wrap() {
  _ssenc_sivkey "$1" wrap
  _ssenc_hex2esc "$2"
  _N=1 _ADP=("$_AD_SLOT") _PT=("$_E")
  _ssenc_siv_enc_batch "$_KM" "$_KE"
  _WRAPPED=${_TAG[0]}${_CT[0]}
}

# _ssenc_unwrap KEKHEX WRAPPEDHEX -> _DEK; returns 1 when it does not authenticate.
_ssenc_unwrap() {
  _ssenc_sivkey "$1" wrap
  _N=1 _ADP=("$_AD_SLOT") _TAG=("${2:0:32}") _CTH=("${2:32}")
  _ssenc_siv_dec_batch "$_KM" "$_KE"
  ((_OK[0])) || return 1
  _DEK=${_PT[0]//\\x/}
  return 0
}

# ---------------------------------------------------------------------------------------
# header parsing (SPEC.md section 2)
# ---------------------------------------------------------------------------------------

_RE_LINES='^#ssenc1 lines ws=([01]) pad=(0|[1-9][0-9]{0,3})$'
_RE_BLOB='^#ssenc1 blob chunk=([1-9][0-9]{0,6})$'
_RE_PW='^#slot pw argon2id m=([1-9][0-9]{0,7}),t=([1-9][0-9]?),p=([1-9][0-9]?) ([A-Za-z0-9_-]+) ([A-Za-z0-9_-]+)$'
_RE_SSH='^#slot ssh (ssh-ed25519|ssh-rsa) (SHA256:[A-Za-z0-9+/]{43}) ([A-Za-z0-9_-]+) ([A-Za-z0-9_-]+)$'
_RE_SEAL='^#seal [A-Za-z0-9_-]+$'
_RE_KDF='^m=([1-9][0-9]{0,7}),t=([1-9][0-9]?),p=([1-9][0-9]?)$'
_RE_INT='^(0|[1-9][0-9]*)$'

_ssenc_kdf_in_range() { # M T P
  (($3 >= 1 && $3 <= 16 && $2 >= 1 && $2 <= 64 && $1 >= 8 * $3 && $1 <= 4194304))
}

# Escaped header line (terminator included) -> _TEXT; returns 1 when it cannot be a
# header line (NUL byte or longer than 1024 bytes).
_ssenc_line_text() {
  local l=$1
  [[ $l == *"$_X0A" ]] && l=${l%"$_X0A"}
  [[ $l == *"$_X0D" ]] && l=${l%"$_X0D"}
  _TEXT=
  ((${#l} > 4096)) && return 1
  [[ $l == *"$_X00"* ]] && return 1
  printf -v _TEXT -- "$l"
  return 0
}

_ssenc_field() { # B64URL BYTES WHAT -> _HEX
  # deliberate: any failed check falls through to the error
  # shellcheck disable=SC2015
  _ssenc_b64d "$1" && ((${#_HEX} == $2 * 2)) || _ssenc_die MALFORMED "invalid $3 in header"
}

_ssenc_parse_slot() {
  local line=$1 i=$P_NSLOTS
  if [[ $line =~ $_RE_PW ]]; then
    local m=${BASH_REMATCH[1]} t=${BASH_REMATCH[2]} p=${BASH_REMATCH[3]} s=${BASH_REMATCH[4]} w=${BASH_REMATCH[5]}
    P_STYPE[i]=pw P_SM[i]=$m P_ST[i]=$t P_SP[i]=$p
    _ssenc_field "$s" 16 "password slot salt"
    P_SSALT[i]=$_HEX
    _ssenc_field "$w" 48 "wrapped key"
    P_SWRAP[i]=$_HEX
    _ssenc_kdf_in_range "$m" "$t" "$p" || _ssenc_die MALFORMED "argon2id parameters out of range in header"
  elif [[ $line =~ $_RE_SSH ]]; then
    local kt=${BASH_REMATCH[1]} fp=${BASH_REMATCH[2]} s=${BASH_REMATCH[3]} w=${BASH_REMATCH[4]}
    P_STYPE[i]=ssh P_SKT[i]=$kt P_SFP[i]=$fp
    _ssenc_field "$s" 32 "ssh slot salt"
    P_SSALT[i]=$_HEX
    _ssenc_field "$w" 48 "wrapped key"
    P_SWRAP[i]=$_HEX
  else
    _ssenc_die MALFORMED "unrecognised slot line in header"
  fi
  P_SLOTLINE[i]=$line
  P_NSLOTS=$((i + 1))
}

# _ssenc_parse FILE -> P_MODE P_WS P_PAD P_CHUNK P_HEADER P_NSLOTS P_S*[] P_SEAL P_HASSEAL
#                      P_BODYOFF (offset of the body in bytes), P_FILE
_ssenc_parse() {
  local file=$1 size win=16384 l n off complete first status
  local pre_slot='\x23\x73\x6c\x6f\x74\x20' pre_seal='\x23\x73\x65\x61\x6c\x20'
  _ssenc_size "$file"
  size=$_SIZE
  P_FILE=$file
  ((size == 0)) && _ssenc_die MALFORMED "not an ssenc1 file (missing '#ssenc1' header)"
  while :; do
    head -c "$win" "$file" | _ssenc_esclines >"$_T/hdr"
    P_MODE=lines P_WS=1 P_PAD=0 P_CHUNK=0 P_HEADER='' P_NSLOTS=0 P_SEAL='' P_HASSEAL=0
    P_STYPE=() P_SM=() P_ST=() P_SP=() P_SKT=() P_SFP=() P_SSALT=() P_SWRAP=() P_SLOTLINE=()
    off=0 first=1 status='done'
    while IFS= read -r l || [[ -n $l ]]; do
      n=$((${#l} / 4))
      complete=1
      [[ $l != *"$_X0A" ]] && ((win < size)) && complete=0
      if ((first)); then
        if ((!complete)); then status='more'; break; fi
        first=0
        _ssenc_line_text "$l" && [[ $_TEXT == "#ssenc1 "* ]] ||
          _ssenc_die MALFORMED "not an ssenc1 file (missing '#ssenc1' header)"
        P_HEADER=$_TEXT
        if [[ $_TEXT =~ $_RE_LINES ]]; then
          P_WS=${BASH_REMATCH[1]} P_PAD=${BASH_REMATCH[2]}
          ((P_PAD > 4096)) && _ssenc_die MALFORMED "pad out of range in header"
        elif [[ $_TEXT =~ $_RE_BLOB ]]; then
          P_MODE=blob P_CHUNK=${BASH_REMATCH[1]}
          ((P_CHUNK > 1048576)) && _ssenc_die MALFORMED "chunk out of range in header"
        else
          _ssenc_die MALFORMED "invalid '#ssenc1' header line"
        fi
      elif [[ $l == "$pre_slot"* ]]; then
        if ((!complete)); then status='more'; break; fi
        ((P_HASSEAL)) && _ssenc_die MALFORMED "slot line after seal line"
        _ssenc_line_text "$l" || _ssenc_die MALFORMED "unrecognised slot line in header"
        _ssenc_parse_slot "$_TEXT"
      elif [[ $l == "$pre_seal"* ]]; then
        if ((!complete)); then status='more'; break; fi
        ((P_HASSEAL)) || [[ $P_MODE != lines ]] && _ssenc_die MALFORMED "unexpected seal line"
        _ssenc_line_text "$l" && [[ $_TEXT =~ $_RE_SEAL ]] || _ssenc_die MALFORMED "invalid seal line"
        _ssenc_field "${_TEXT:6}" 32 "seal"
        P_SEAL=$_HEX P_HASSEAL=1
      else
        # First body line - unless it is cut short and could still become a header line.
        if ((!complete && n < 6)); then status='more'; else status=body; fi
        break
      fi
      off=$((off + n))
    done <"$_T/hdr"
    # status=done: every line of the window was a header line; if the window does not
    # cover the whole file, more header lines may follow.
    [[ $status == 'done' ]] && ((win < size)) && status='more'
    [[ $status != more ]] && break
    win=$((win * 8))
  done
  ((P_NSLOTS == 0)) && _ssenc_die MALFORMED "header has no key slots"
  P_BODYOFF=$off
}

_ssenc_body() { # prints the body of the parsed file
  tail -c "+$((P_BODYOFF + 1))" "$P_FILE"
}

# ---------------------------------------------------------------------------------------
# ssh keys (SPEC.md section 2.3)
# ---------------------------------------------------------------------------------------

# Reads the SSH string at hex offset $2 of $1 -> _STR (hex), _NEXT; returns 1 if truncated.
_ssenc_ssh_string() {
  local h=$1 o=$2 len
  ((o + 8 <= ${#h})) || return 1
  len=$((0x${h:o:8} * 2))
  ((o + 8 + len <= ${#h})) || return 1
  _STR=${h:o+8:len}
  _NEXT=$((o + 8 + len))
  return 0
}

_ssenc_hex2text() { # hex -> _TEXT ("" when it holds a NUL byte)
  _TEXT=
  [[ $1 == *00* ]] && {
    local i
    for ((i = 0; i < ${#1}; i += 2)); do [[ ${1:i:2} == 00 ]] && return 1; done
  }
  _ssenc_hex2esc "$1"
  printf -v _TEXT -- "$_E"
}

# Fingerprint of a key blob (hex) -> _FP
_ssenc_ssh_fp() {
  local out
  _ssenc_hex2esc "$1"
  out=$(printf -- "$_E" | openssl dgst -sha256 2>/dev/null)
  out=${out##*= }
  [[ ${#out} -eq 64 && $out != *[!0-9a-f]* ]] || _ssenc_die ENV "openssl dgst (SHA-256) failed"
  _ssenc_b64e "$out"
  _B64=${_B64//-/+}
  _FP="SHA256:${_B64//_//}"
}

# Lists the keys of the agent once -> _AG_TYPE[], _AG_B64[], _AG_FP[], _AG_HEX[]
_ssenc_agent_load() {
  ((_AG_LOADED)) && return 0
  local rc line parts n=0
  [[ -n ${SSH_AUTH_SOCK:-} ]] || _ssenc_die ENV "ssh-agent not available: SSH_AUTH_SOCK is not set"
  command -v ssh-add >/dev/null 2>&1 || _ssenc_die ENV "required tool 'ssh-add' not found in PATH"
  ssh-add -L >"$_T/agent.keys" 2>"$_T/agent.err" </dev/null
  rc=$?
  # 0 = keys listed, 1 = agent reachable but empty, anything else = no agent
  ((rc == 0 || rc == 1)) || _ssenc_die ENV "ssh-agent at $SSH_AUTH_SOCK: cannot connect ($(head -n 1 "$_T/agent.err"))"
  _AG_TYPE=() _AG_B64=() _AG_FP=() _AG_HEX=()
  if ((rc == 0)); then
    while IFS= read -r line || [[ -n $line ]]; do
      read -r -a parts <<<"$line"
      ((${#parts[@]} >= 2)) || continue
      _ssenc_b64std_d "${parts[1]}" || continue
      _AG_TYPE[n]=${parts[0]} _AG_B64[n]=${parts[1]} _AG_HEX[n]=$_HEX
      _ssenc_ssh_fp "$_HEX"
      _AG_FP[n]=$_FP
      n=$((n + 1))
    done <"$_T/agent.keys"
  fi
  _AG_LOADED=1
}

# _ssenc_ssh_resolve KIND VALUE   (KIND = sshpub: VALUE is the text of a public key file;
# KIND = sshfp: VALUE is a SHA256:... fingerprint) -> R_HEX R_KT R_FP
_ssenc_ssh_resolve() {
  local kind=$1 value=$2 line parts i found=0
  R_HEX='' R_KT='' R_FP=
  if [[ $kind == sshpub ]]; then
    while IFS= read -r line || [[ -n $line ]]; do
      line=${line%$'\r'}
      read -r -a parts <<<"$line"
      ((${#parts[@]} >= 2)) || continue
      [[ ${parts[0]} == ssh-* || ${parts[0]} == ecdsa-* || ${parts[0]} == sk-* ]] || continue
      _ssenc_b64std_d "${parts[1]}" || continue
      local blob=$_HEX
      _ssenc_ssh_string "$blob" 0 || _ssenc_die ENV "invalid ssh public key"
      _ssenc_hex2text "$_STR"
      if [[ $_TEXT == "${parts[0]}" ]]; then
        R_HEX=$blob R_KT=$_TEXT found=1
        break
      fi
    done <<<"$value"
    ((found)) || _ssenc_die ENV "not an OpenSSH public key"
  else
    _ssenc_agent_load
    for ((i = 0; i < ${#_AG_FP[@]}; i++)); do
      if [[ ${_AG_FP[i]} == "$value" ]]; then
        R_HEX=${_AG_HEX[i]} found=1
        break
      fi
    done
    ((found)) || _ssenc_die ENV "key $value is not loaded in ssh-agent (check: ssh-add -l)"
    _ssenc_ssh_string "$R_HEX" 0 || _ssenc_die ENV "invalid ssh public key"
    _ssenc_hex2text "$_STR"
    R_KT=$_TEXT
  fi
  [[ $R_KT == ssh-ed25519 || $R_KT == ssh-rsa ]] ||
    _ssenc_die ENV "unsupported ssh key type '$R_KT': only ssh-ed25519 and ssh-rsa give deterministic signatures"
  _ssenc_ssh_fp "$R_HEX"
  R_FP=$_FP
}

# KEK of the resolved key (R_*) for SALTHEX -> _KEK. Signs through the agent only: the
# public key is written to a private temp file, so ssh-keygen can never fall back to a
# private key file lying next to the user's .pub file (and never prompts).
_ssenc_ssh_kek() {
  local salt=$1 i idx=-1 line b64='' in=0 sig expected alg_end
  _ssenc_agent_load
  for ((i = 0; i < ${#_AG_FP[@]}; i++)); do
    [[ ${_AG_FP[i]} == "$R_FP" ]] && { idx=$i; break; }
  done
  ((idx >= 0)) || _ssenc_die ENV "ssh-agent could not sign with key $R_FP (is it loaded? check: ssh-add -l)"
  command -v ssh-keygen >/dev/null 2>&1 || _ssenc_die ENV "required tool 'ssh-keygen' not found in PATH"
  printf '%s %s\n' "${_AG_TYPE[idx]}" "${_AG_B64[idx]}" >"$_T/key.pub"
  _ssenc_hex2esc "$salt"
  if ! printf -- "ssenc1 ssh slot$_E" |
    SSH_ASKPASS_REQUIRE=never ssh-keygen -Y sign -f "$_T/key.pub" -n "ssenc-v1@stopsopa" >"$_T/sig" 2>"$_T/sig.err"; then
    _ssenc_die ENV "ssh-agent could not sign with key $R_FP (is it loaded? check: ssh-add -l)"
  fi
  while IFS= read -r line || [[ -n $line ]]; do
    line=${line%$'\r'}
    case $line in
      "-----BEGIN SSH SIGNATURE-----") in=1 ;;
      "-----END SSH SIGNATURE-----") in=0 ;;
      *) ((in)) && b64+=$line ;;
    esac
  done <"$_T/sig"
  expected=ssh-ed25519
  [[ $R_KT == ssh-rsa ]] && expected=rsa-sha2-512
  # SSHSIG: "SSHSIG" u32(version) string(publickey) string(namespace) string(reserved)
  #         string(hash_algorithm) string(signature)
  _ssenc_b64std_d "$b64" && [[ ${_HEX:0:20} == 53534853494700000001 ]] ||
    _ssenc_die ENV "ssh-keygen -Y sign produced no usable signature (OpenSSH >= 8.1 is required)"
  sig=$_HEX
  _NEXT=20
  for i in 1 2 3 4 5; do
    _ssenc_ssh_string "$sig" "$_NEXT" || _ssenc_die ENV "ssh-keygen -Y sign produced a truncated signature"
  done
  sig=$_STR
  _ssenc_ssh_string "$sig" 0 || _ssenc_die ENV "ssh signer returned an unexpected signature (need $expected)"
  _ssenc_hex2text "$_STR"
  alg_end=$_NEXT
  # deliberate: any failed check falls through to the error
  # shellcheck disable=SC2015
  [[ $_TEXT == "$expected" ]] && _ssenc_ssh_string "$sig" "$alg_end" && ((_NEXT == ${#sig})) ||
    _ssenc_die ENV "ssh signer returned an unexpected signature (need $expected)"
  _ssenc_hkdf "$sig" "$salt" "ssenc1/ssh-kek"
  _KEK=${_HK[0]}
}

# ---------------------------------------------------------------------------------------
# key slots. Keys are given as parallel arrays: <prefix>_KIND[i] = pw | sshpub | sshfp,
# <prefix>_VAL[i] = password as hex | text of the public key file | fingerprint.
# ---------------------------------------------------------------------------------------

# _ssenc_make_slots DEKHEX KIND-ARRAY VALUE-ARRAY M T P -> _SLOTS[]
_ssenc_make_slots() {
  local dek=$1 kn=$2 vn=$3 m=$4 t=$5 p=$6 i n ref kind val salt
  ref="${kn}[@]"
  local kinds=("${!ref}")
  n=${#kinds[@]}
  ((n > 0)) || _ssenc_die USAGE "at least one key is required"
  _SLOTS=()
  for ((i = 0; i < n; i++)); do
    [[ ${kinds[i]} == pw ]] || continue
    ref="${vn}[$i]"
    val=${!ref}
    [[ -n $val ]] || _ssenc_die USAGE "password must not be empty"
    _ssenc_rand 16
    salt=$_RAND
    _ssenc_argon2 "$val" "$salt" "$m" "$t" "$p"
    _ssenc_wrap "$_KEK" "$dek"
    _ssenc_b64e "$salt"
    local s64=$_B64
    _ssenc_b64e "$_WRAPPED"
    _SLOTS+=("#slot pw argon2id m=$m,t=$t,p=$p $s64 $_B64")
  done
  for ((i = 0; i < n; i++)); do
    kind=${kinds[i]}
    [[ $kind == pw ]] && continue
    ref="${vn}[$i]"
    _ssenc_ssh_resolve "$kind" "${!ref}"
    _ssenc_rand 32
    salt=$_RAND
    _ssenc_ssh_kek "$salt"
    _ssenc_wrap "$_KEK" "$dek"
    _ssenc_b64e "$salt"
    local s64=$_B64
    _ssenc_b64e "$_WRAPPED"
    _SLOTS+=("#slot ssh $R_KT $R_FP $s64 $_B64")
  done
}

# Opens the parsed file (P_*) with the first key that fits -> _DEK, or dies with AUTH.
_ssenc_open() {
  local kn=$1 vn=$2 i j n ref kind val
  ref="${kn}[@]"
  local kinds=("${!ref}")
  n=${#kinds[@]}
  ((n > 0)) || _ssenc_die USAGE "at least one key is required"
  for ((i = 0; i < n; i++)); do
    kind=${kinds[i]}
    ref="${vn}[$i]"
    val=${!ref}
    if [[ $kind == pw ]]; then
      [[ -n $val ]] || _ssenc_die USAGE "password must not be empty"
      for ((j = 0; j < P_NSLOTS; j++)); do
        [[ ${P_STYPE[j]} == pw ]] || continue
        _ssenc_argon2 "$val" "${P_SSALT[j]}" "${P_SM[j]}" "${P_ST[j]}" "${P_SP[j]}"
        _ssenc_unwrap "$_KEK" "${P_SWRAP[j]}" && return 0
      done
    else
      _ssenc_ssh_resolve "$kind" "$val"
      for ((j = 0; j < P_NSLOTS; j++)); do
        [[ ${P_STYPE[j]} == ssh && ${P_SFP[j]} == "$R_FP" ]] || continue
        _ssenc_ssh_kek "${P_SSALT[j]}"
        _ssenc_unwrap "$_KEK" "${P_SWRAP[j]}" && return 0
      done
    fi
  done
  _ssenc_die AUTH "${_AUTH_MESSAGE:-no key slot could be opened with the given key}"
}

# ---------------------------------------------------------------------------------------
# lines mode (SPEC.md section 3)
# ---------------------------------------------------------------------------------------

# Splits an escaped line (without terminator) -> _LEAD, _CORE, _TRAIL
_ssenc_wsplit() {
  local l=$1 s t nl nt
  _LEAD='' _TRAIL='' _CORE=$l
  case $l in
    "$_X20"* | "$_X09"* | *"$_X20" | *"$_X09") ;;
    *) return 0 ;;
  esac
  # Shadow string: S for every space/tab, the other bytes stay "\xHH".
  s=${l//"$_X20"/S}
  s=${s//"$_X09"/S}
  if [[ $s != *\\* ]]; then
    _LEAD=$l _CORE=
    return 0
  fi
  t=${s%%\\*}
  nl=${#t}
  t=${s##*\\x??}
  nt=${#t}
  _LEAD=${l:0:nl*4}
  _TRAIL=${l:${#l}-nt*4}
  _CORE=${l:nl*4:${#l}-(nl+nt)*4}
}

# Removes the terminator of an escaped line -> _LINE, _TERM
_ssenc_term() {
  _LINE=$1 _TERM=
  if [[ $_LINE == *"$_X0A" ]]; then
    _LINE=${_LINE%"$_X0A"}
    _TERM=$_X0A
    if [[ $_LINE == *"$_X0D" ]]; then
      _LINE=${_LINE%"$_X0D"}
      _TERM=$_X0D$_X0A
    fi
  fi
}

# _ssenc_lines_encrypt DEK WS PAD PLAINFILE BODYFILE
_ssenc_lines_encrypt() {
  local dek=$1 ws=$2 pad=$3 plain=$4 body=$5 l k=0 i n len
  local -a pre post item
  _ssenc_sivkey "$dek" line
  local kmac=$_KM kenc=$_KE
  _ssenc_esclines <"$plain" >"$_T/lines"
  _N=0 _PT=() _ADP=()
  while IFS= read -r l || [[ -n $l ]]; do
    _ssenc_term "$l"
    if ((ws)); then
      _ssenc_wsplit "$_LINE"
      if [[ -z $_CORE ]]; then
        pre[k]=$l post[k]='' item[k]=-1
        k=$((k + 1))
        continue
      fi
    else
      _LEAD='' _TRAIL='' _CORE=$_LINE
    fi
    if ((pad > 0)); then
      len=$((${#_CORE} / 4))
      _CORE+=$_X80${_SSENC_Z:0:$(((pad - len % pad - 1) * 4))}
    fi
    pre[k]=$_LEAD post[k]=$_TRAIL$_TERM item[k]=$_N
    _PT[_N]=$_CORE _ADP[_N]=$_AD_NONE
    _N=$((_N + 1))
    k=$((k + 1))
  done <"$_T/lines"
  n=$k
  _ssenc_siv_enc_batch "$kmac" "$kenc"
  for ((k = 0; k < n; k++)); do
    i=${item[k]}
    if ((i < 0)); then
      printf -- "${pre[k]}"
    else
      _ssenc_b64e "${_TAG[i]}${_CT[i]}"
      printf -- "${pre[k]}$_B64${post[k]}"
    fi
  done >"$body" || _ssenc_die ENV "cannot write to the temporary directory"
}

# _ssenc_lines_decrypt DEK PAD OUTFILE    (body of the parsed file P_*)
_ssenc_lines_decrypt() {
  local dek=$1 pad=$2 out=$3 l k=0 i n bad=0 tok p q tail
  local -a pre post item
  _ssenc_sivkey "$dek" line
  local kmac=$_KM kenc=$_KE
  _ssenc_body | _ssenc_esclines >"$_T/lines"
  _N=0 _TAG=() _CTH=() _ADP=()
  while IFS= read -r l || [[ -n $l ]]; do
    _ssenc_term "$l"
    _ssenc_wsplit "$_LINE"
    if [[ -z $_CORE ]]; then
      pre[k]=$l post[k]='' item[k]=-1
      k=$((k + 1))
      continue
    fi
    tok=
    if [[ $_CORE == *"$_X00"* ]]; then
      bad=$((k + 1))
      break
    fi
    printf -v tok -- "$_CORE"
    if ! _ssenc_b64d "$tok" || ((${#_HEX} < 32)); then
      bad=$((k + 1))
      break
    fi
    pre[k]=$_LEAD post[k]=$_TRAIL$_TERM item[k]=$_N
    _TAG[_N]=${_HEX:0:32} _CTH[_N]=${_HEX:32} _ADP[_N]=$_AD_NONE
    _N=$((_N + 1))
    k=$((k + 1))
  done <"$_T/lines"
  n=$k
  _ssenc_siv_dec_batch "$kmac" "$kenc"
  # Errors are reported in line order, exactly like a line-by-line implementation.
  for ((k = 0; k < n; k++)); do
    i=${item[k]}
    if ((i < 0)); then
      printf -- "${pre[k]}"
      continue
    fi
    ((_OK[i])) || _ssenc_die AUTH "authentication failed (wrong key or modified data)"
    p=${_PT[i]}
    if ((pad > 0)); then
      # padding = 0x80 followed only by 0x00: cut at the last 0x80
      q=${p%"$_X80"*}
      [[ $q != "$p" ]] || _ssenc_die MALFORMED "invalid line padding"
      tail=${p:${#q}+4}
      [[ -z ${tail//"$_X00"/} ]] || _ssenc_die MALFORMED "invalid line padding"
      p=$q
    fi
    printf -- "${pre[k]}$p${post[k]}"
  done >"$out" || exit $?
  ((bad == 0)) || _ssenc_die MALFORMED "line $bad is not a valid encrypted line"
}

# ---------------------------------------------------------------------------------------
# blob mode (SPEC.md section 4)
# ---------------------------------------------------------------------------------------

# Chunks smaller than this go through the batched engine, larger ones are streamed.
_SSENC_STREAM_MIN=4096

# u64be(9) || u64be(index) || final, as printf escapes -> _E
_ssenc_blob_adp() {
  local h
  printf -v h '0000000000000009%016x%02x' "$1" "$2"
  _ssenc_hex2esc "$h"
}

# _ssenc_blob_encrypt DEK CHUNK PLAINFILE BODYFILE
_ssenc_blob_encrypt() {
  local dek=$1 chunk=$2 plain=$3 body=$4 size count i l line tag f final
  _ssenc_sivkey "$dek" blob
  local kmac=$_KM kenc=$_KE
  _ssenc_size "$plain"
  size=$_SIZE
  count=$(((size + chunk - 1) / chunk))
  ((count == 0)) && count=1
  if ((chunk < _SSENC_STREAM_MIN)); then
    _N=0 _PT=() _ADP=()
    if ((size == 0)); then
      _PT[0]='' _N=1
    else
      xxd -p <"$plain" | tr -d '\n' | fold -w $((chunk * 2)) | sed -e 's/../\\x&/g' >"$_T/chunks"
      while IFS= read -r l || [[ -n $l ]]; do
        _PT[_N]=$l
        _N=$((_N + 1))
      done <"$_T/chunks"
    fi
    ((_N == count)) || _ssenc_die ENV "internal error: chunk count mismatch"
    for ((i = 0; i < _N; i++)); do
      _ssenc_blob_adp "$i" $((i == _N - 1))
      _ADP[i]=$_E
    done
    _ssenc_siv_enc_batch "$kmac" "$kenc"
    for ((i = 0; i < _N; i++)); do
      printf '%s%s\n' "${_TAG[i]}" "${_CT[i]}"
    done | xxd -r -p >"$_T/records" || _ssenc_die ENV "cannot write to the temporary directory"
  else
    mkdir "$_T/c" || _ssenc_die ENV "cannot write to the temporary directory"
    if ((size == 0)); then
      : >"$_T/c/aaaaaa"
    else
      split -a 6 -b "$chunk" "$plain" "$_T/c/" || _ssenc_die ENV "split failed"
    fi
    i=0
    for f in "$_T"/c/*; do
      final=$((i == count - 1))
      _ssenc_blob_adp "$i" "$final"
      printf -- "$_E" >"$_T/pfx"
      line=$(cat "$_T/pfx" "$f" | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$kmac" 2>/dev/null)
      tag=${line##*= }
      [[ ${#tag} -eq 64 && $tag != *[!0-9a-f]* ]] || _ssenc_die ENV "openssl dgst (HMAC-SHA-256) failed (run envverify.sh)"
      tag=${tag:0:32}
      _ssenc_iv "$tag"
      _ssenc_hex2esc "$tag"
      printf -- "$_E"
      openssl enc -aes-256-ctr -K "$kenc" -iv "$_IV" -in "$f" 2>/dev/null ||
        _ssenc_die ENV "openssl enc (AES-256-CTR) failed (run envverify.sh)"
      i=$((i + 1))
    done >"$_T/records" || exit $?
    ((i == count)) || _ssenc_die ENV "internal error: chunk count mismatch"
  fi
  base64 <"$_T/records" | tr -d '\n=' | tr '/+' '_-' | fold -w 76 >"$body"
  # fold does not terminate the last line
  [[ $(tail -c 1 "$body" | xxd -p) == 0a ]] || printf '\n' >>"$body"
  _ssenc_size "$body"
  local rsize=$((size + count * 16))
  ((_SIZE == (rsize * 4 + 2) / 3 + ((rsize * 4 + 2) / 3 + 75) / 76)) ||
    _ssenc_die ENV "base64 encoding failed (is 'base64' installed?)"
}

_ssenc_base64_decode() {
  if [[ -z ${_B64_DFLAG:-} ]]; then
    if [[ $(printf 'QUJD' | base64 -d 2>/dev/null) == ABC ]]; then
      _B64_DFLAG=-d
    elif [[ $(printf 'QUJD' | base64 -D 2>/dev/null) == ABC ]]; then
      _B64_DFLAG=-D
    else
      _ssenc_die ENV "required tool 'base64' not found or unable to decode"
    fi
  fi
  base64 "$_B64_DFLAG"
}

# _ssenc_blob_decrypt DEK CHUNK OUTFILE    (body of the parsed file P_*)
_ssenc_blob_decrypt() {
  local dek=$1 chunk=$2 out=$3 n junk last v padding='' rec count rsize i l f tag line short=0
  _ssenc_body | tr -d ' \t\r\n' >"$_T/b64"
  _ssenc_size "$_T/b64"
  n=$_SIZE
  junk=$(tr -d 'A-Za-z0-9_-' <"$_T/b64" | wc -c)
  ((junk == 0 && n > 0 && n % 4 != 1)) || _ssenc_die MALFORMED "blob body is not valid base64url"
  # Like the reference, ignore unused trailing bits: make the last character canonical
  # so that strict decoders accept it too.
  last=$(tail -c 1 "$_T/b64")
  v=${_SSENC_D[$last]}
  case $((n % 4)) in
    2) last=${_SSENC_A[v & 48]} padding="==" ;;
    3) last=${_SSENC_A[v & 60]} padding="=" ;;
  esac
  {
    head -c $((n - 1)) "$_T/b64"
    printf '%s%s\n' "$last" "$padding"
  } | tr '_-' '/+' | _ssenc_base64_decode >"$_T/raw" 2>/dev/null
  _ssenc_size "$_T/raw"
  rsize=$_SIZE
  ((rsize == n * 3 / 4)) || _ssenc_die MALFORMED "blob body is not valid base64url"
  ((rsize > 0)) || _ssenc_die MALFORMED "blob body is not valid base64url"
  _ssenc_sivkey "$dek" blob
  local kmac=$_KM kenc=$_KE
  rec=$((chunk + 16))
  count=$(((rsize + rec - 1) / rec))
  # Only the last record can be shorter than a tag; the ones before it are still
  # checked first, as the reference does.
  ((rsize - (count - 1) * rec < 16)) && short=1
  if ((chunk < _SSENC_STREAM_MIN)); then
    _N=0 _TAG=() _CTH=() _ADP=()
    xxd -p <"$_T/raw" | tr -d '\n' | fold -w $((rec * 2)) >"$_T/records"
    while IFS= read -r l || [[ -n $l ]]; do
      ((${#l} < 32)) && break
      _TAG[_N]=${l:0:32} _CTH[_N]=${l:32}
      _ssenc_blob_adp "$_N" $((_N == count - 1))
      _ADP[_N]=$_E
      _N=$((_N + 1))
    done <"$_T/records"
    ((_N == count - short)) || _ssenc_die ENV "internal error: record count mismatch"
    _ssenc_siv_dec_batch "$kmac" "$kenc"
    for ((i = 0; i < _N; i++)); do
      ((_OK[i])) || _ssenc_die AUTH "authentication failed (wrong key or modified data)"
      printf -- "${_PT[i]}"
    done >"$out" || exit $?
  else
    mkdir "$_T/r" || _ssenc_die ENV "cannot write to the temporary directory"
    split -a 6 -b "$rec" "$_T/raw" "$_T/r/" || _ssenc_die ENV "split failed"
    i=0
    : >"$out"
    for f in "$_T"/r/*; do
      ((i == count - 1 && short)) && break
      tag=$(xxd -p -l 16 "$f")
      _ssenc_iv "$tag"
      _ssenc_blob_adp "$i" $((i == count - 1))
      printf -- "$_E" >"$_T/pfx"
      line=$(tail -c +17 "$f" | openssl enc -d -aes-256-ctr -K "$kenc" -iv "$_IV" 2>/dev/null |
        tee -a "$out" | cat "$_T/pfx" - | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$kmac" 2>/dev/null)
      line=${line##*= }
      [[ ${#line} -eq 64 && $line != *[!0-9a-f]* ]] || _ssenc_die ENV "openssl dgst (HMAC-SHA-256) failed (run envverify.sh)"
      [[ ${line:0:32} == "$tag" ]] || _ssenc_die AUTH "authentication failed (wrong key or modified data)"
      i=$((i + 1))
    done
    ((i == count - short)) || _ssenc_die ENV "internal error: record count mismatch"
  fi
  ((short)) && _ssenc_die MALFORMED "ciphertext shorter than the authentication tag"
  _ssenc_size "$out"
  ((_SIZE == rsize - count * 16)) || _ssenc_die ENV "internal error: decrypted size mismatch (openssl enc failed?)"
}

# ---------------------------------------------------------------------------------------
# operations (SPEC.md section 5)
# ---------------------------------------------------------------------------------------

# HMAC-SHA-256(K_seal, header-line || LF || body-file) -> _SEAL (hex)
_ssenc_seal() {
  local dek=$1 header=$2 bodycmd=$3 line
  _ssenc_hkdf "$dek" "" "ssenc1/seal"
  line=$({
    printf '%s\n' "$header"
    "$bodycmd"
  } | openssl dgst -sha256 -mac HMAC -macopt "hexkey:${_HK[0]}" 2>/dev/null)
  line=${line##*= }
  [[ ${#line} -eq 64 && $line != *[!0-9a-f]* ]] || _ssenc_die ENV "openssl dgst (HMAC-SHA-256) failed (run envverify.sh)"
  _SEAL=$line
}

_ssenc_cat_newbody() { cat "$_T/body"; }

# Well-formed UTF-8 sequences of two to four bytes (RFC 3629: no overlong forms, no
# surrogates, nothing above U+10FFFF), as a regular expression over bytes (LC_ALL=C).
_RE_UTF8_TAIL=$'[\x80-\xbf]'
_RE_UTF8=$'[\xc2-\xdf]'"$_RE_UTF8_TAIL|"$'\xe0[\xa0-\xbf]'"$_RE_UTF8_TAIL|"$'[\xe1-\xec\xee\xef]'"$_RE_UTF8_TAIL$_RE_UTF8_TAIL|"
_RE_UTF8+=$'\xed[\x80-\x9f]'"$_RE_UTF8_TAIL|"$'\xf0[\x90-\xbf]'"$_RE_UTF8_TAIL$_RE_UTF8_TAIL|"
_RE_UTF8+=$'[\xf1-\xf3]'"$_RE_UTF8_TAIL$_RE_UTF8_TAIL$_RE_UTF8_TAIL|"$'\xf4[\x80-\x8f]'"$_RE_UTF8_TAIL$_RE_UTF8_TAIL"

# _ssenc_detect_mode FILE -> _MODE: what --mode auto picks. "lines" when the file is text,
# which means it has no NUL byte and is valid UTF-8 (so also when it is empty), otherwise
# "blob". The whole file is examined.
_ssenc_detect_mode() {
  local size
  size=$(($(wc -c <"$1")))
  _MODE=blob
  # a NUL byte: not text
  (($(tr -d '\000' <"$1" | wc -c) == size)) || return 0
  _MODE=lines
  # only ASCII: text
  (($(tr -d '\000-\177' <"$1" | wc -c) == 0)) && return 0
  # Remove every well-formed multi-byte sequence; a byte >= 0x80 that is left over was not
  # part of one. (No sequence contains a newline, so working line by line loses nothing.)
  (($(sed -E "s/$_RE_UTF8//g" <"$1" | tr -d '\000-\177' | wc -c) == 0)) || _MODE=blob
  return 0
}

# _ssenc_check_layout MODE PAD CHUNK SEAL
_ssenc_check_layout() {
  [[ $1 == lines || $1 == blob ]] || _ssenc_die USAGE "mode must be 'lines', 'blob' or 'auto'"
  (($2 >= 0 && $2 <= 4096)) || _ssenc_die USAGE "pad must be an integer from 0 to 4096"
  (($3 >= 1 && $3 <= 1048576)) || _ssenc_die USAGE "chunk must be an integer from 1 to 1048576"
  (($4)) && [[ $1 != lines ]] && _ssenc_die USAGE "seal is only available in lines mode"
  return 0
}

# _ssenc_parse_kdf PROFILE -> _KDF_M _KDF_T _KDF_P
_ssenc_parse_kdf() {
  case $1 in
    "" | default) _KDF_M=65536 _KDF_T=3 _KDF_P=4 ;;
    strong) _KDF_M=1048576 _KDF_T=4 _KDF_P=4 ;;
    *)
      [[ $1 =~ $_RE_KDF ]] || _ssenc_die USAGE "invalid kdf profile '$1' (use default, strong or m=..,t=..,p=..)"
      _KDF_M=${BASH_REMATCH[1]} _KDF_T=${BASH_REMATCH[2]} _KDF_P=${BASH_REMATCH[3]}
      ;;
  esac
  _ssenc_kdf_in_range "$_KDF_M" "$_KDF_T" "$_KDF_P" ||
    _ssenc_die USAGE "kdf parameters out of range (8*p <= m <= 4194304, 1 <= t <= 64, 1 <= p <= 16)"
}

# _ssenc_assemble DEK MODE WS PAD CHUNK SEAL PLAINFILE OUTFILE   (slot lines in _SLOTS[])
_ssenc_assemble() {
  local dek=$1 mode=$2 ws=$3 pad=$4 chunk=$5 seal=$6 plain=$7 out=$8 header s
  if [[ $mode == lines ]]; then
    header="#ssenc1 lines ws=$ws pad=$pad"
    _ssenc_lines_encrypt "$dek" "$ws" "$pad" "$plain" "$_T/body"
  else
    header="#ssenc1 blob chunk=$chunk"
    _ssenc_blob_encrypt "$dek" "$chunk" "$plain" "$_T/body"
  fi
  {
    printf '%s\n' "$header"
    for s in "${_SLOTS[@]}"; do printf '%s\n' "$s"; done
    if ((seal)); then
      _ssenc_seal "$dek" "$header" _ssenc_cat_newbody
      _ssenc_b64e "$_SEAL"
      printf '#seal %s\n' "$_B64"
    fi
    cat "$_T/body"
  } >"$out" || exit $?
}

# Decrypts the parsed file (P_*) with DEK into OUTFILE.
_ssenc_decrypt_parsed() {
  local dek=$1 out=$2
  if ((P_HASSEAL)); then
    _ssenc_seal "$dek" "$P_HEADER" _ssenc_body
    [[ $_SEAL == "$P_SEAL" ]] ||
      _ssenc_die AUTH "seal does not match: lines were added, removed, reordered or modified"
  fi
  if [[ $P_MODE == lines ]]; then
    _ssenc_lines_decrypt "$dek" "$P_PAD" "$out"
  else
    _ssenc_blob_decrypt "$dek" "$P_CHUNK" "$out"
  fi
}

# ---------------------------------------------------------------------------------------
# command line (SPEC.md section 7)
# ---------------------------------------------------------------------------------------

# Content of a password file minus one trailing LF or CRLF, as hex -> _PWHEX
_ssenc_read_password_file() {
  local h
  [[ -r $1 && ! -d $1 ]] || _ssenc_die USAGE "cannot read password file $1"
  h=$(xxd -p <"$1" 2>/dev/null | tr -d '\n')
  [[ $h == *0a ]] && h=${h%0a}
  [[ $h == *0d ]] && h=${h%0d}
  _PWHEX=$h
}

_ssenc_text_hex() { # text -> _PWHEX
  _PWHEX=$(printf '%s' "$1" | xxd -p | tr -d '\n')
}

# --ssh-key argument -> _SK_KIND, _SK_VAL
_ssenc_ssh_key_arg() {
  if [[ $1 == SHA256:* ]]; then
    _SK_KIND=sshfp _SK_VAL=$1
    return 0
  fi
  [[ -r $1 && ! -d $1 ]] || _ssenc_die USAGE "cannot read ssh public key file $1"
  _SK_KIND=sshpub
  # A public key file is text; NUL bytes cannot be part of a valid one.
  _SK_VAL=$(tr -d '\000' <"$1" 2>/dev/null) || _ssenc_die USAGE "cannot read ssh public key file $1"
}

_ssenc_read_input() { # [PATH] -> $_T/in
  if [[ -n ${1+x} ]]; then
    # deliberate: any failed check falls through to the error
    # shellcheck disable=SC2015
    [[ -r $1 && ! -d $1 ]] && cat -- "$1" >"$_T/in" 2>/dev/null || _ssenc_die USAGE "cannot read input: $1"
  else
    cat >"$_T/in" || _ssenc_die USAGE "cannot read input"
  fi
}

_ssenc_write_output() { # FILE [PATH]
  if [[ -n ${2+x} ]]; then
    cat "$1" >"$2" 2>/dev/null || _ssenc_die USAGE "cannot write output: $2"
  else
    cat "$1"
  fi
}

# _ssenc_op COMMAND OPTIONS...
_ssenc_op() {
  local cmd=$1
  shift
  local in_path out_path pw_file new_pw_file previous kdf a v
  local fresh=0 rewrap_only=0 have_in=0 have_out=0 have_pw_file=0 have_new_pw_file=0 have_previous=0 have_kdf=0
  local o_mode='' o_ws='' o_pad='' o_chunk='' o_seal=
  local -a ssh_keys=() new_ssh_keys=()

  while (($# > 0)); do
    a=$1
    shift
    # options with a value
    case $a in
      -i | -o | --password-file | --ssh-key | --new-password-file | --new-ssh-key | --mode | --pad | --chunk | --kdf | --previous)
        _ssenc_only "$cmd" "$a"
        (($# > 0)) || _ssenc_usage "option $a needs a value"
        v=$1
        shift
        ;;
      --no-preserve-ws | --seal | --fresh | --rewrap-only) _ssenc_only "$cmd" "$a" ;;
      *) _ssenc_usage "unknown option '$a'" ;;
    esac
    case $a in
      -i) in_path=$v have_in=1 ;;
      -o) out_path=$v have_out=1 ;;
      --password-file) pw_file=$v have_pw_file=1 ;;
      --ssh-key) ssh_keys+=("$v") ;;
      --new-password-file) new_pw_file=$v have_new_pw_file=1 ;;
      --new-ssh-key) new_ssh_keys+=("$v") ;;
      --mode)
        [[ $v == lines || $v == blob || $v == auto ]] || _ssenc_usage "--mode must be lines, blob or auto"
        o_mode=$v
        ;;
      --pad | --chunk)
        [[ $v =~ $_RE_INT ]] || _ssenc_usage "option $a needs a non-negative integer"
        ((${#v} > 9)) && v=999999999
        if [[ $a == --pad ]]; then o_pad=$v; else o_chunk=$v; fi
        ;;
      --kdf) kdf=$v have_kdf=1 ;;
      --previous) previous=$v have_previous=1 ;;
      --no-preserve-ws) o_ws=0 ;;
      --seal) o_seal=1 ;;
      --fresh) fresh=1 ;;
      --rewrap-only) rewrap_only=1 ;;
    esac
  done
  ((have_previous && fresh)) && _ssenc_usage "--previous and --fresh exclude each other"
  ((have_kdf)) || kdf=

  if [[ $cmd == inspect ]]; then
    if ((have_in)); then _ssenc_read_input "$in_path"; else _ssenc_read_input; fi
    _ssenc_parse "$_T/in"
    _ssenc_inspect_json >"$_T/out"
    _ssenc_write_output "$_T/out"
    return 0
  fi

  # keys
  local -a K_KIND=() K_VAL=() NK_KIND=() NK_VAL=()
  local have_pw=0 pw_hex='' s
  if ((have_pw_file)); then
    _ssenc_read_password_file "$pw_file"
    pw_hex=$_PWHEX have_pw=1
  elif [[ -n ${SSENC_PASSWORD+x} ]]; then
    _ssenc_text_hex "$SSENC_PASSWORD"
    pw_hex=$_PWHEX have_pw=1
  elif ((${#ssh_keys[@]} == 0)); then
    if [[ ! -t 0 ]] || ((!have_in)); then
      _ssenc_usage "no key given: use --password-file, SSENC_PASSWORD or --ssh-key"
    fi
    printf 'ssenc password: ' >&2
    IFS= read -rs s || true
    printf '\n' >&2
    _ssenc_text_hex "$s"
    pw_hex=$_PWHEX have_pw=1
    s=
  fi
  ((have_pw)) && [[ -z $pw_hex ]] && _ssenc_usage "password must not be empty"
  if [[ $cmd == encrypt ]]; then
    if ((have_pw)); then
      K_KIND+=(pw)
      K_VAL+=("$pw_hex")
    fi
    for s in "${ssh_keys[@]}"; do
      _ssenc_ssh_key_arg "$s"
      K_KIND+=("$_SK_KIND")
      K_VAL+=("$_SK_VAL")
    done
  else
    ((${#ssh_keys[@]} > 1)) && _ssenc_usage "'$cmd' takes a single --ssh-key"
    if ((${#ssh_keys[@]} == 1)); then
      _ssenc_ssh_key_arg "${ssh_keys[0]}"
      K_KIND+=("$_SK_KIND")
      K_VAL+=("$_SK_VAL")
    else
      K_KIND+=(pw)
      K_VAL+=("$pw_hex")
    fi
  fi

  case $cmd in
    encrypt)
      local have_prev=0 auto_prev=0
      if ((have_previous)); then
        # deliberate: any failed check falls through to the error
        # shellcheck disable=SC2015
        [[ -r $previous && ! -d $previous ]] && cat -- "$previous" >"$_T/prev" 2>/dev/null ||
          _ssenc_die USAGE "cannot read --previous file: $previous"
        have_prev=1
      elif ((!fresh && have_out)) && [[ -f $out_path && -r $out_path ]]; then
        if [[ $(head -c 8 "$out_path" 2>/dev/null | xxd -p) == 237373656e633120 ]]; then
          cat -- "$out_path" >"$_T/prev" 2>/dev/null || _ssenc_die USAGE "cannot read the existing output file: $out_path"
          have_prev=1 auto_prev=1
        fi
      fi
      if ((have_in)); then _ssenc_read_input "$in_path"; else _ssenc_read_input; fi
      local mode ws pad chunk seal dek
      if ((have_prev)); then
        _ssenc_parse "$_T/prev"
        ((auto_prev)) && _AUTH_MESSAGE="the existing output file cannot be opened with this key; use --fresh to overwrite it with a new data key"
        _ssenc_open K_KIND K_VAL
        _AUTH_MESSAGE=
        dek=$_DEK
        # auto keeps the mode of the previous version: a file must not flip between lines
        # and blob because of one edit
        mode=${o_mode:-$P_MODE}
        [[ $mode == auto ]] && mode=$P_MODE
        if [[ -n $o_ws ]]; then ws=$o_ws; elif [[ $P_MODE == lines ]]; then ws=$P_WS; else ws=1; fi
        if [[ -n $o_pad ]]; then pad=$o_pad; elif [[ $P_MODE == lines ]]; then pad=$P_PAD; else pad=16; fi
        if [[ -n $o_chunk ]]; then chunk=$o_chunk; elif [[ $P_MODE == blob ]]; then chunk=$P_CHUNK; else chunk=65536; fi
        if [[ -n $o_seal ]]; then seal=1; elif [[ $mode == lines ]] && ((P_HASSEAL)); then seal=1; else seal=0; fi
        _ssenc_check_layout "$mode" "$pad" "$chunk" "$seal"
        _SLOTS=("${P_SLOTLINE[@]}")
      else
        mode=${o_mode:-lines} ws=${o_ws:-1} pad=${o_pad:-16} chunk=${o_chunk:-65536} seal=${o_seal:-0}
        if [[ $mode == auto ]]; then
          _ssenc_detect_mode "$_T/in"
          mode=$_MODE
        fi
        _ssenc_check_layout "$mode" "$pad" "$chunk" "$seal"
        _ssenc_parse_kdf "$kdf"
        _ssenc_rand 32
        dek=$_RAND
        _ssenc_make_slots "$dek" K_KIND K_VAL "$_KDF_M" "$_KDF_T" "$_KDF_P"
      fi
      _ssenc_assemble "$dek" "$mode" "$ws" "$pad" "$chunk" "$seal" "$_T/in" "$_T/out"
      ;;
    decrypt)
      if ((have_in)); then _ssenc_read_input "$in_path"; else _ssenc_read_input; fi
      _ssenc_parse "$_T/in"
      _ssenc_open K_KIND K_VAL
      _ssenc_decrypt_parsed "$_DEK" "$_T/out"
      ;;
    rekey)
      local have_new_pw=0 new_pw_hex=
      if ((have_new_pw_file)); then
        _ssenc_read_password_file "$new_pw_file"
        new_pw_hex=$_PWHEX have_new_pw=1
      elif [[ -n ${SSENC_NEW_PASSWORD+x} ]]; then
        _ssenc_text_hex "$SSENC_NEW_PASSWORD"
        new_pw_hex=$_PWHEX have_new_pw=1
      fi
      if ((have_new_pw)); then
        [[ -n $new_pw_hex ]] || _ssenc_usage "new password must not be empty"
        NK_KIND+=(pw)
        NK_VAL+=("$new_pw_hex")
      fi
      for s in "${new_ssh_keys[@]}"; do
        _ssenc_ssh_key_arg "$s"
        NK_KIND+=("$_SK_KIND")
        NK_VAL+=("$_SK_VAL")
      done
      ((${#NK_KIND[@]} > 0)) || _ssenc_usage "no new key given: use --new-password-file, SSENC_NEW_PASSWORD or --new-ssh-key"
      if ((have_in)); then _ssenc_read_input "$in_path"; else _ssenc_read_input; fi
      _ssenc_parse "$_T/in"
      _ssenc_open K_KIND K_VAL
      local old_dek=$_DEK
      _ssenc_parse_kdf "$kdf"
      if ((rewrap_only)); then
        _ssenc_make_slots "$old_dek" NK_KIND NK_VAL "$_KDF_M" "$_KDF_T" "$_KDF_P"
        {
          printf '%s\n' "$P_HEADER"
          for s in "${_SLOTS[@]}"; do printf '%s\n' "$s"; done
          if ((P_HASSEAL)); then
            _ssenc_b64e "$P_SEAL"
            printf '#seal %s\n' "$_B64"
          fi
          _ssenc_body
        } >"$_T/out" || exit $?
      else
        _ssenc_decrypt_parsed "$old_dek" "$_T/plain"
        local r_pad=16 r_chunk=65536
        [[ $P_MODE == lines ]] && r_pad=$P_PAD
        [[ $P_MODE == blob ]] && r_chunk=$P_CHUNK
        _ssenc_rand 32
        local new_dek=$_RAND
        _ssenc_make_slots "$new_dek" NK_KIND NK_VAL "$_KDF_M" "$_KDF_T" "$_KDF_P"
        _ssenc_assemble "$new_dek" "$P_MODE" "$P_WS" "$r_pad" "$r_chunk" "$P_HASSEAL" "$_T/plain" "$_T/out"
      fi
      ;;
  esac
  if ((have_out)); then _ssenc_write_output "$_T/out" "$out_path"; else _ssenc_write_output "$_T/out"; fi
  return 0
}

# Dies unless OPTION is valid for COMMAND.
_ssenc_only() {
  local ok=0
  case $2 in
    -i) ok=1 ;;
    -o | --password-file | --ssh-key) [[ $1 != inspect ]] && ok=1 ;;
    --kdf) [[ $1 == encrypt || $1 == rekey ]] && ok=1 ;;
    --new-password-file | --new-ssh-key | --rewrap-only) [[ $1 == rekey ]] && ok=1 ;;
    *) [[ $1 == encrypt ]] && ok=1 ;;
  esac
  ((ok)) || _ssenc_usage "option $2 is not valid for '$1'"
}

_ssenc_inspect_json() {
  local i slots='' sep=
  for ((i = 0; i < P_NSLOTS; i++)); do
    if [[ ${P_STYPE[i]} == pw ]]; then
      slots+="$sep{\"type\":\"pw\",\"kdf\":\"argon2id\",\"m\":${P_SM[i]},\"t\":${P_ST[i]},\"p\":${P_SP[i]}}"
    else
      slots+="$sep{\"type\":\"ssh\",\"keyType\":\"${P_SKT[i]}\",\"fingerprint\":\"${P_SFP[i]}\"}"
    fi
    sep=,
  done
  if [[ $P_MODE == lines ]]; then
    local ws=true seal=false
    ((P_WS)) || ws=false
    ((P_HASSEAL)) && seal=true
    printf '{"format":"ssenc1","mode":"lines","ws":%s,"pad":%s,"seal":%s,"slots":[%s]}\n' "$ws" "$P_PAD" "$seal" "$slots"
  else
    printf '{"format":"ssenc1","mode":"blob","chunk":%s,"slots":[%s]}\n' "$P_CHUNK" "$slots"
  fi
}

_ssenc_cli() {
  local cmd=$1
  case $cmd in
    encrypt | decrypt | rekey | inspect) ;;
    *) _ssenc_usage "unknown command '$cmd'" ;;
  esac
  _ssenc_op "$@"
}

# ---------------------------------------------------------------------------------------
# public functions
# ---------------------------------------------------------------------------------------

ssenc_encrypt() (_ssenc_run _ssenc_op encrypt "$@")
ssenc_decrypt() (_ssenc_run _ssenc_op decrypt "$@")
ssenc_rekey() (_ssenc_run _ssenc_op rekey "$@")
ssenc_inspect() (_ssenc_run _ssenc_op inspect "$@")

ssenc_cli() (
  if [[ ${1-} == --version ]]; then
    printf 'ssenc bash %s\n' "$SSENC_VERSION"
    exit 0
  fi
  if (($# == 0)) || [[ $1 == --help || $1 == -h ]]; then
    _ssenc_usage_text
    exit 0
  fi
  _ssenc_run _ssenc_cli "$@"
)

# _ssenc_prim NAME ARGS... - the primitives behind the ssenc_<name> test entry points.
_ssenc_prim() {
  local what=$1 h a want=4
  shift
  case $what in
    hkdf32) want=3 ;;
    sivkey) want=2 ;;
    argon2id) want=5 ;;
  esac
  (($# == want)) || _ssenc_die USAGE "ssenc_$what: expected $want arguments"
  case $what in
    hkdf32 | sivkey) set -- "$@" "" "" ;;
    argon2id)
      [[ $3 =~ $_RE_INT && $4 =~ $_RE_INT && $5 =~ $_RE_INT ]] || _ssenc_die USAGE "ssenc_argon2id: m, t and p must be integers"
      ;;
  esac
  # hex arguments: all four of the siv functions, the first two of the others
  local -a hexargs=("$1" "$2")
  [[ $what == siv_* ]] && hexargs+=("$3" "$4")
  [[ $what == sivkey ]] && hexargs=("$1")
  for a in "${hexargs[@]}"; do
    [[ -z $a ]] || _ssenc_ishex "$a" || _ssenc_die USAGE "ssenc_$what: binary arguments must be lowercase hex"
  done
  case $what in
    hkdf32)
      _ssenc_hkdf "$1" "$2" "$3"
      printf '%s\n' "${_HK[0]}"
      ;;
    sivkey)
      _ssenc_sivkey "$1" "$2"
      printf '%s %s\n' "$_KM" "$_KE"
      ;;
    siv_encrypt)
      printf -v h '%016x' $((${#3} / 2))
      _ssenc_hex2esc "$h$3"
      _N=1 _ADP=("$_E")
      _ssenc_hex2esc "$4"
      _PT=("$_E")
      _ssenc_siv_enc_batch "$1" "$2"
      printf '%s\n' "${_TAG[0]}${_CT[0]}"
      ;;
    siv_decrypt)
      ((${#4} >= 32)) || _ssenc_die MALFORMED "ciphertext shorter than the authentication tag"
      printf -v h '%016x' $((${#3} / 2))
      _ssenc_hex2esc "$h$3"
      _N=1 _ADP=("$_E") _TAG=("${4:0:32}") _CTH=("${4:32}")
      _ssenc_siv_dec_batch "$1" "$2"
      ((_OK[0])) || _ssenc_die AUTH "authentication failed (wrong key or modified data)"
      printf '%s\n' "${_PT[0]//\\x/}"
      ;;
    argon2id)
      _ssenc_argon2 "$@"
      printf '%s\n' "$_KEK"
      ;;
  esac
}

ssenc_hkdf32() (_ssenc_run _ssenc_prim hkdf32 "$@")
ssenc_sivkey() (_ssenc_run _ssenc_prim sivkey "$@")
ssenc_siv_encrypt() (_ssenc_run _ssenc_prim siv_encrypt "$@")
ssenc_siv_decrypt() (_ssenc_run _ssenc_prim siv_decrypt "$@")
ssenc_argon2id() (_ssenc_run _ssenc_prim argon2id "$@")
