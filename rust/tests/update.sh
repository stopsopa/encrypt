# End-to-end test of "ssenc --update" (rust/src/update.rs): the binary replacing itself with a release.
#
#   /bin/bash rust/tests/update.sh        (from any directory; rust/test.sh runs it after cargo test)
#
# Nothing is downloaded from github. Releases are faked in a local directory (SSENC_RELEASES),
# with the same layout github has:
#   <dir>/latest                    tag of the latest release (github: redirect)
#   <dir>/download/<tag>/<file>     the binary of the platform and SHA256SUMS.txt
#
# In this order:
#   1. a local build (version "dev") refuses to update; a wrong argument prints the usage.
#   2. binaries with real versions v9.9.8 and v9.9.9 are compiled (env var SSENC_VERSION, read by
#      build.rs) and put into the faked releases. v9.9.8 is "installed" and started through a symlink.
#   3. --update --check: only says what is installed and what is the latest.
#   4. nothing is replaced without a "yes": no terminal to ask on, and the answer "n".
#   5. releases which are not what they should be, each one refused: checksum doesn't match, the
#      binary reports another version, the file is not a program, no checksum for this platform,
#      a tag which doesn't exist, no releases at all.
#   6. the update confirmed with "y": v9.9.8 -> v9.9.9. Then "up to date".
#   7. an older release on request (--update v9.9.8), without asking (SSENC_CONFIRM=false).
#   8. a directory which is not writable: explained, nothing changed.
#
# After every step "installed" checks which binary is installed: after every failure it has to be
# byte for byte the one which was there before, with no other file left next to it.
#
# Needs: cargo. ssenc is compiled three times here (v9.9.8, v9.9.9 and "dev" again at the end, also
# when the test fails, so rust/target/release/ssenc is again what rust/compile.sh makes).
# Everything the test creates is in rust/target/update-test (ignored by git, kept to look at it).
# Skipped (exit code 0) on a platform for which no binaries are released.
# Exit code: 0 when every check passed, 1 otherwise.

_SHELL="$(ps -p $$ -o comm=)"; # bash || sh || zsh
_SHELL="$(basename ${_SHELL//-/})"
case ${_SHELL} in
  zsh)
    _DIR="$( cd "$( dirname "${(%):-%x}" )" && pwd -P )"
    ;;
  sh)
    # be carefull this will not work when sourcing this file in sh shell
    # will though work when called /bin/sh my_script.sh from any shell
    _DIR="$( cd "$( dirname "${0}" )" && pwd -P )"
    ;;
  *)
    _DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd -P )"
    ;;
esac

# directory of the crate
_RUST="$(cd "${_DIR}/.." && pwd)"

# name of the file of a release for this machine, the same names ssenc looks for (src/update.rs)
# and the release workflow publishes
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) ASSET="ssenc-darwin-arm64" ;;
  Linux-x86_64) ASSET="ssenc-linux-x64" ;;
  Linux-aarch64 | Linux-arm64) ASSET="ssenc-linux-arm64" ;;
  *)
    echo "skip - update: no released binaries for $(uname -s)-$(uname -m)"
    exit 0
    ;;
esac

BUILT="${_RUST}/target/release/ssenc"
WORK="${_RUST}/target/update-test"

# what the previous run left
if [[ -d "${WORK}" ]]; then
  chmod -R u+w "${WORK}"
  rm -rf "${WORK}"
fi
mkdir -p "${WORK}"

# the test must not depend on what the caller has in the environment
unset SSENC_RELEASES SSENC_CONFIRM SSENC_TEST_ANSWER SSENC_VERSION

PASSED=0
FAILED=0

# build_version <version> <output>
# compiles ssenc with the given version built in and copies the result to <output>.
# The output of cargo is shown only when the build failed. The copy is started with --version:
# it has to report exactly the version asked for, otherwise the rest would test nothing.
function build_version {
  if ! SSENC_VERSION="${1}" cargo build --release --locked --manifest-path "${_RUST}/Cargo.toml" > "${WORK}/cargo.log" 2>&1; then
    cat "${WORK}/cargo.log"
    echo "${0} error: cargo build of version >${1}< failed"
    exit 1
  fi
  cp "${BUILT}" "${2}"
  if [[ "$("${2}" --version)" != "ssenc rust ${1}" ]]; then
    echo "${0} error: binary built for the test reports >$("${2}" --version)< instead of >ssenc rust ${1}<"
    exit 1
  fi
}

# The builds below leave a binary with a faked version in target/release. Whatever happens,
# the last build is "dev" again: what rust/compile.sh makes and what the other tests expect.
function restore_dev {
  SSENC_VERSION="" cargo build --release --locked --manifest-path "${_RUST}/Cargo.toml" > "${WORK}/cargo-dev.log" 2>&1
}
trap restore_dev EXIT

# sha256 in the format of SHA256SUMS.txt ("<hash>  <name>"): sha256sum on Linux, shasum on macOS
function sha256 {
  if command -v sha256sum > /dev/null 2>&1; then
    sha256sum "${@}"
  else
    shasum -a 256 "${@}"
  fi
}

# release <directory of releases> <tag> <binary>
# puts <binary> into the faked releases as the file of this platform of release <tag>, with
# SHA256SUMS.txt next to it (cd: the name in it has to be without a directory)
function release {
  local TARGET_DIR="${1}/download/${2}"
  mkdir -p "${TARGET_DIR}"
  cp "${3}" "${TARGET_DIR}/${ASSET}"
  (cd "${TARGET_DIR}" && sha256 "${ASSET}" > SHA256SUMS.txt)
}

# check <label> <expected exit code> <fragment> [<fragment>...]
# runs ${COMMAND} (stdout and stderr together, stdin /dev/null) and passes when the exit code is
# the expected one and every fragment is in the output. Fragment starting with "=" has to be the
# whole output.
function check {
  local LABEL="${1}"
  local EXPECTED_CODE="${2}"
  shift 2
  local OUTPUT
  OUTPUT="$(eval "${COMMAND}" 2>&1 < /dev/null)"
  local CODE="${?}"
  local PROBLEM=""
  if [[ "${CODE}" != "${EXPECTED_CODE}" ]]; then
    PROBLEM="exit code >${CODE}<, expected >${EXPECTED_CODE}<"
  fi
  local FRAGMENT
  for FRAGMENT in "${@}"; do
    if [[ "${FRAGMENT}" == "="* ]]; then
      if [[ "${OUTPUT}" != "${FRAGMENT#=}" ]]; then
        PROBLEM="${PROBLEM} the whole output should be >${FRAGMENT#=}<"
      fi
    elif [[ "${OUTPUT}" != *"${FRAGMENT}"* ]]; then
      PROBLEM="${PROBLEM} no >${FRAGMENT}< in the output"
    fi
  done
  if [[ -z "${PROBLEM}" ]]; then
    PASSED=$((PASSED + 1))
    echo "ok   - update: ${LABEL}"
  else
    FAILED=$((FAILED + 1))
    cat <<EEE
FAIL - update: ${LABEL}
  command: ${COMMAND}
  problem: ${PROBLEM}
  output:
${OUTPUT}
EEE
  fi
}

# installed <tag> <label>
# one more check: the installed file is byte for byte the binary of release <tag>, nothing else is
# in its directory (no downloaded file, no backup copy), what is "in PATH" is still a symlink and,
# started through it, the binary reports <tag>.
function installed {
  EXPECTED_TAG="${1}"
  COMMAND='cmp "${INSTALLED}" "${REL}/download/${EXPECTED_TAG}/${ASSET}" && ls -A "${WORK}/installed" && [[ -L "${SSENC}" ]] && "${SSENC}" --version'
  check "installed binary is ${1}: ${2}" 0 "=ssenc
ssenc rust ${1}"
}

# ---------- 1. a local build (version "dev") refuses to update ----------

build_version dev "${WORK}/bin-dev"

# it is not a release, so it can't know whether a release is newer. The refusal comes before
# anything is read: SSENC_RELEASES points to a directory which doesn't exist yet. Exit code 4 (ENV).
COMMAND='SSENC_RELEASES="${WORK}/releases" SSENC_CONFIRM=false "${WORK}/bin-dev" --update'
check "dev build refuses" 4 "ssenc: ENV: this binary is a local build (version dev)"

# --update takes "--check" or a tag, "--what" is neither: the usage, exit code 1 (USAGE)
COMMAND='"${WORK}/bin-dev" --update --what'
check "unknown argument: usage" 1 "ssenc: USAGE: wrong arguments of --update" "ssenc --update --check"

# ---------- 2. binaries with real versions, faked releases, v9.9.8 installed ----------

build_version v9.9.8 "${WORK}/bin-v9.9.8"
build_version v9.9.9 "${WORK}/bin-v9.9.9"

REL="${WORK}/releases"
release "${REL}" v9.9.8 "${WORK}/bin-v9.9.8"
release "${REL}" v9.9.9 "${WORK}/bin-v9.9.9"
echo "v9.9.9" > "${REL}/latest"

# installed in its own directory and reachable through a symlink in another one (the way a binary
# in ~/bin often is): --update has to replace the real file and leave the link alone
mkdir "${WORK}/installed" "${WORK}/path"
INSTALLED="${WORK}/installed/ssenc"
cp "${REL}/download/v9.9.8/${ASSET}" "${INSTALLED}"
chmod 755 "${INSTALLED}"
ln -s "${INSTALLED}" "${WORK}/path/ssenc"
SSENC="${WORK}/path/ssenc"
# canonical path, the way ssenc prints it (on macOS the temporary directories are behind a symlink)
INSTALLED_REAL="$(cd "${WORK}/installed" && pwd -P)/ssenc"

# from now on every --update reads the faked releases (single checks override it with a broken copy)
export SSENC_RELEASES="${REL}"

installed v9.9.8 "before"

# ---------- 3. --check: only information ----------

COMMAND='"${SSENC}" --update --check'
check "--update --check" 0 "=installed: v9.9.8
latest: v9.9.9
to install it: ssenc --update"

installed v9.9.8 "after --check"

# ---------- 4. nothing is changed when the answer is not yes ----------

# stdin is /dev/null: there is nobody to answer. It must not hang and must not assume "yes".
COMMAND='"${SSENC}" --update'
check "no terminal" 4 "needs confirmation and there is no terminal, use SSENC_CONFIRM=false"

installed v9.9.8 "after no terminal"

# "no" is not an error. The file named before the question is the real one, not the symlink.
COMMAND='SSENC_TEST_ANSWER="n" "${SSENC}" --update'
check "answer no: the real file is named, not the symlink" 0 "files to replace:
  ${INSTALLED_REAL}" "nothing changed"

installed v9.9.8 "after answer no"

# ---------- 5. releases which are not what they should be ----------

# the binary of v9.9.9 got one more byte after its checksum was written: a broken download
BAD="${WORK}/releases-bad-checksum"
cp -R "${REL}" "${BAD}"
echo "x" >> "${BAD}/download/v9.9.9/${ASSET}"

COMMAND='SSENC_RELEASES="${WORK}/releases-bad-checksum" SSENC_CONFIRM=false "${SSENC}" --update'
check "broken download" 4 "checksum of downloaded >${ASSET}< doesn't match SHA256SUMS.txt, nothing was changed"

installed v9.9.8 "after broken download"

# release v9.9.9 holds the binary of v9.9.8, with a checksum which is right for that file:
# the checksum passes, running it has to catch it
BAD="${WORK}/releases-bad-version"
cp -R "${REL}" "${BAD}"
release "${BAD}" v9.9.9 "${WORK}/bin-v9.9.8"

COMMAND='SSENC_RELEASES="${WORK}/releases-bad-version" SSENC_CONFIRM=false "${SSENC}" --update'
check "binary of another version: checksum passed, caught by running it" 4 "checksum ok: ${ASSET}" "downloaded binary doesn't work here, nothing was changed"

installed v9.9.8 "after binary of another version"

# the file of v9.9.9 is a text file, again with a right checksum: what a binary for another
# platform would look like too
BAD="${WORK}/releases-not-a-binary"
cp -R "${REL}" "${BAD}"
echo "not a program" > "${WORK}/garbage"
release "${BAD}" v9.9.9 "${WORK}/garbage"

COMMAND='SSENC_RELEASES="${WORK}/releases-not-a-binary" SSENC_CONFIRM=false "${SSENC}" --update'
check "not a binary" 4 "downloaded binary doesn't work here, nothing was changed"

installed v9.9.8 "after not a binary"

# SHA256SUMS.txt of v9.9.9 has a line only for some other file: there is no "skip the verification"
BAD="${WORK}/releases-no-sum"
cp -R "${REL}" "${BAD}"
echo "$(printf 'a%.0s' $(seq 1 64))  some-other-file" > "${BAD}/download/v9.9.9/SHA256SUMS.txt"

COMMAND='SSENC_RELEASES="${WORK}/releases-no-sum" SSENC_CONFIRM=false "${SSENC}" --update'
check "no checksum" 4 "there is no checksum of >${ASSET}< in SHA256SUMS.txt"

installed v9.9.8 "after no checksum"

COMMAND='SSENC_CONFIRM=false "${SSENC}" --update v1.2.3'
check "release which doesn't exist" 4 "is >v1.2.3< a published release with all files?"

installed v9.9.8 "after release which doesn't exist"

COMMAND='SSENC_RELEASES="${WORK}/no-releases" SSENC_CONFIRM=false "${SSENC}" --update'
check "no release at all" 4 "can't find out the latest release"

installed v9.9.8 "after no release at all"

# ---------- 6. the update, confirmed ----------

COMMAND='SSENC_TEST_ANSWER="y" "${SSENC}" --update'
check "update: tested before and after replacing" 0 "test ok: downloaded binary reports ssenc rust v9.9.9" "test ok: installed binary reports ssenc rust v9.9.9" "ssenc updated: v9.9.8 -> v9.9.9"

installed v9.9.9 "after update"

COMMAND='"${SSENC}" --update'
check "up to date: nothing to do" 0 "=installed: v9.9.9
latest: v9.9.9
ssenc is up to date"

installed v9.9.9 "after up to date"

# ---------- 7. an older release, on request ----------

COMMAND='SSENC_CONFIRM=false "${SSENC}" --update v9.9.8'
check "older release" 0 "requested: v9.9.8" "ssenc updated: v9.9.9 -> v9.9.8"

installed v9.9.8 "after older release"

# ---------- 8. a directory which is not writable ----------

# root can write everywhere, chmod would not stop it: this part is skipped for root
if [[ "$(id -u)" != "0" ]]; then
  chmod 555 "${WORK}/installed"

  COMMAND='SSENC_CONFIRM=false "${SSENC}" --update'
  check "directory not writable" 4 "the directory has to be writable for the update"

  chmod 755 "${WORK}/installed"

  installed v9.9.8 "after directory not writable"
fi

cat <<EEE

update: ${PASSED} passed, ${FAILED} failed
EEE

if [[ "${FAILED}" != "0" ]]; then
  echo "${0} error: ${FAILED} checks of ssenc --update failed"
  exit 1
fi
