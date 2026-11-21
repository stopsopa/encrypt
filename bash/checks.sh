#!/usr/bin/env bash
# Environment checks shared by envverify.sh and install.sh. Sourced, not executed.
#
# This file must run under ANY bash, including the bash 3.2 of macOS, because its job is
# to report that such a bash is too old. So: no associative arrays, no mapfile, no ${x,,}.
#
# run_checks prints one "[ OK ]" / "[FAIL]" / "[WARN]" block per item and sets:
#     CHECK_PROBLEMS   number of [FAIL] blocks
#     CHECK_FIXES[]    package-manager commands that would repair them (no duplicates)
#     CHECK_OPTIONAL[] the same for [WARN] items

CHECK_PROBLEMS=0
CHECK_FIXES=()
CHECK_OPTIONAL=()

case "$(uname -s 2>/dev/null)" in
  Darwin) CHECK_OS=mac ;;
  *) CHECK_OS=linux ;;
esac

# pkg_cmd MAC-COMMAND LINUX-COMMAND -> the one for this system
pkg_cmd() {
  if [[ $CHECK_OS == mac ]]; then printf '%s' "$1"; else printf '%s' "$2"; fi
}

_check_add() { # ARRAYNAME VALUE - append unless already there
  local name=$1 value=$2 cur
  eval "for cur in \"\${${name}[@]-}\"; do [[ \$cur == \"\$value\" ]] && return 0; done"
  eval "${name}+=(\"\$value\")"
}

ok() {
  printf '[ OK ] %s\n' "$1"
}

fail() { # TITLE FOUND NEED FIX
  printf '[FAIL] %s\n' "$1"
  printf '       found:  %s\n' "$2"
  printf '       need:   %s\n' "$3"
  printf '       fix:    %s\n' "$4"
  CHECK_PROBLEMS=$((CHECK_PROBLEMS + 1))
  _check_add CHECK_FIXES "$4"
}

warn() { # TITLE FIX
  printf '[WARN] %s\n' "$1"
  printf '       fix:    %s\n' "$2"
  _check_add CHECK_OPTIONAL "$2"
}

check_bash() {
  local fix
  fix=$(pkg_cmd 'brew install bash     (then run the scripts with that bash first in PATH)' 'sudo apt-get install -y bash')
  if ((BASH_VERSINFO[0] >= 4)); then
    ok "bash ${BASH_VERSION%%[^0-9.]*} (>= 4.0)"
  else
    fail "bash: too old" "$BASH ($BASH_VERSION)" "bash >= 4.0 (arrays, mapfile, printf -v)" "$fix"
  fi
}

check_openssl() {
  local fix path ver out detail zero64 zero32
  # shellcheck disable=SC2016  # the fix text is shown to the user, not expanded here
  fix=$(pkg_cmd 'brew install openssl@3 && export PATH="$(brew --prefix openssl@3)/bin:$PATH"' \
    'sudo apt-get install -y openssl     (only on releases that ship OpenSSL >= 3.2: Ubuntu 25.04+, Debian 13+; older ones need a newer openssl first in PATH)')
  if ! path=$(command -v openssl 2>/dev/null) || [[ -z $path ]]; then
    fail "openssl: not found" "nothing on PATH" "OpenSSL >= 3.2" "$fix"
    return
  fi
  ver=$(openssl version 2>/dev/null | head -n 1 | sed -e 's/^\([^ ]* [^ ]*\).*/\1/')
  zero64=0000000000000000000000000000000000000000000000000000000000000000
  zero32=00000000000000000000000000000000
  local bad=0

  # Argon2id: the second vector of tests/vectors/primitives.json
  out=$(openssl kdf -keylen 32 -kdfopt hexpass:636f727265637420686f727365206261747465727920737461706c65 \
    -kdfopt hexsalt:ffeeddccbbaa99887766554433221100 -kdfopt iter:2 -kdfopt memcost:64 -kdfopt lanes:4 ARGON2ID 2>&1 | tr -d ':\n' | tr 'A-F' 'a-f')
  if [[ $out != a261359b268e0ef265e8fa92eb404c49bfc06c79178ef883b6e57104c575c70d ]]; then
    if openssl kdf -help 2>&1 | grep -qi 'invalid command'; then
      detail="'kdf' command missing"
    else
      detail="'kdf' command has no working ARGON2ID"
    fi
    fail "openssl: Argon2id not available" "$path ($ver) — $detail" "OpenSSL >= 3.2" "$fix"
    bad=1
  fi

  # AES-256 of the zero block with the zero key (FIPS-197 style known answer), CTR and ECB
  out=$(printf '%s' "$zero32" | xxd -r -p 2>/dev/null | openssl enc -aes-256-ctr -K "$zero64" -iv "$zero32" 2>/dev/null | xxd -p 2>/dev/null | tr -d '\n')
  if [[ $out != dc95c078a2408989ad48a21492842087 ]]; then
    fail "openssl: AES-256-CTR not available" "$path ($ver) — 'openssl enc -aes-256-ctr -K .. -iv ..' gave a wrong or no result" "OpenSSL >= 3.2" "$fix"
    bad=1
  fi
  out=$(printf '%s' "$zero32" | xxd -r -p 2>/dev/null | openssl enc -aes-256-ecb -nopad -K "$zero64" 2>/dev/null | xxd -p 2>/dev/null | tr -d '\n')
  if [[ $out != dc95c078a2408989ad48a21492842087 ]]; then
    fail "openssl: AES-256-ECB not available" "$path ($ver) — 'openssl enc -aes-256-ecb -nopad -K ..' gave a wrong or no result" "OpenSSL >= 3.2" "$fix"
    bad=1
  fi

  # HMAC-SHA-256: RFC 4231 test case 2
  out=$(printf 'what do ya want for nothing?' | openssl dgst -sha256 -mac HMAC -macopt hexkey:4a656665 2>/dev/null)
  out=${out##*= }
  if [[ $out != 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843 ]]; then
    fail "openssl: HMAC-SHA-256 not available" "$path ($ver) — 'openssl dgst -sha256 -mac HMAC -macopt hexkey:..' gave a wrong or no result" "OpenSSL >= 3.2" "$fix"
    bad=1
  fi

  out=$(openssl rand -hex 8 2>/dev/null)
  if [[ ${#out} -ne 16 ]]; then
    fail "openssl: random bytes not available" "$path ($ver) — 'openssl rand -hex 8' failed" "OpenSSL >= 3.2" "$fix"
    bad=1
  fi

  ((bad)) || ok "openssl: $ver at $path (Argon2id, AES-256-CTR/ECB, HMAC-SHA-256 verified)"
}

check_ssh() {
  local fix path ver tmp out
  fix=$(pkg_cmd 'brew install openssh' 'sudo apt-get install -y openssh-client')
  if ! path=$(command -v ssh-keygen 2>/dev/null) || [[ -z $path ]]; then
    fail "ssh-keygen: not found" "nothing on PATH" "OpenSSH >= 8.1 (ssh-keygen -Y sign)" "$fix"
  else
    ver=$(ssh -V 2>&1 | head -n 1)
    ver=${ver%%,*}
    # Functional probe with a throwaway key file; no agent is contacted.
    tmp=$(mktemp -d "${TMPDIR:-/tmp}/ssenc-check.XXXXXX" 2>/dev/null)
    out=
    if [[ -n $tmp && -d $tmp ]]; then
      if ssh-keygen -q -t ed25519 -N '' -C ssenc-probe -f "$tmp/k" >/dev/null 2>&1; then
        out=$(printf 'probe' | SSH_AUTH_SOCK='' ssh-keygen -Y sign -f "$tmp/k" -n ssenc-probe 2>/dev/null)
      fi
      rm -rf "$tmp"
    fi
    if [[ $out == *"BEGIN SSH SIGNATURE"* ]]; then
      ok "ssh-keygen: ${ver:-unknown version} (>= 8.1, -Y sign supported)"
    else
      fail "ssh-keygen: '-Y sign' not supported" "$path (${ver:-unknown version})" "OpenSSH >= 8.1" "$fix"
    fi
  fi
  if ! path=$(command -v ssh-add 2>/dev/null) || [[ -z $path ]]; then
    fail "ssh-add: not found" "nothing on PATH" "ssh-add (part of OpenSSH)" "$fix"
  else
    ok "ssh-add: $path"
  fi
}

check_tools() {
  local fix path out missing tool
  fix=$(pkg_cmd 'brew install vim     (xxd ships with vim; macOS normally has /usr/bin/xxd)' 'sudo apt-get install -y xxd')
  if ! path=$(command -v xxd 2>/dev/null) || [[ -z $path ]]; then
    fail "xxd: not found" "nothing on PATH" "xxd (-p, -r -p, -c, -l)" "$fix"
  else
    out=$(printf 'AB' | xxd -p -c 1 2>/dev/null | tr '\n' ',')$(printf '4142' | xxd -r -p 2>/dev/null)
    if [[ $out == "41,42,AB" ]]; then
      ok "xxd: $path"
    else
      fail "xxd: does not behave as expected" "$path — 'xxd -p -c 1' / 'xxd -r -p' gave '$out'" "xxd (-p, -r -p, -c, -l)" "$fix"
    fi
  fi

  fix=$(pkg_cmd 'brew install coreutils     (macOS normally has /usr/bin/base64)' 'sudo apt-get install -y coreutils')
  if ! path=$(command -v base64 2>/dev/null) || [[ -z $path ]]; then
    fail "base64: not found" "nothing on PATH" "base64 that encodes and decodes (-d or -D)" "$fix"
  else
    out=$(printf 'ABC' | base64 2>/dev/null | tr -d '\n')
    if [[ $out == QUJD && ($(printf 'QUJD' | base64 -d 2>/dev/null) == ABC || $(printf 'QUJD' | base64 -D 2>/dev/null) == ABC) ]]; then
      ok "base64: $path"
    else
      fail "base64: does not behave as expected" "$path — cannot encode and decode (-d / -D)" "base64 that encodes and decodes (-d or -D)" "$fix"
    fi
  fi

  missing=
  for tool in tr sed head tail od dd wc cmp cat fold split mktemp; do
    command -v "$tool" >/dev/null 2>&1 || missing+=" $tool"
  done
  if [[ -z $missing ]]; then
    ok "POSIX tools: tr sed head tail od dd wc cmp cat fold split mktemp"
  else
    fail "POSIX tools: missing" "not on PATH:$missing" "tr sed head tail od dd wc cmp cat fold split mktemp" \
      "$(pkg_cmd 'brew install coreutils gnu-sed diffutils' 'sudo apt-get install -y coreutils sed diffutils')"
  fi
}

check_shellcheck() {
  local path
  if path=$(command -v shellcheck 2>/dev/null) && [[ -n $path ]]; then
    ok "shellcheck: $(shellcheck --version 2>/dev/null | sed -n 's/^version: //p') (optional, used by compile.sh)"
  else
    warn "shellcheck: not found (optional; compile.sh then only runs 'bash -n')" \
      "$(pkg_cmd 'brew install shellcheck' 'sudo apt-get install -y shellcheck')"
  fi
}

run_checks() {
  check_bash
  check_openssl
  check_ssh
  check_tools
  check_shellcheck
}
