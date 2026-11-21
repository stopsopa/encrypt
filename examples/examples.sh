#!/usr/bin/env bash
# Runs the examples: every case-*/ directory, in order, in its three variants
# (rust.sh, ts.sh, bash.sh). Each example prints what it does and checks its own results,
# so this is also a test: the exit code is 1 when any example failed.
#
#   examples/examples.sh                    all cases, all three variants
#   examples/examples.sh 011 ssh            only cases whose directory name contains 011 or ssh
#   examples/examples.sh --lang rust,ts     only these variants (rust, ts, bash)
#   examples/examples.sh --quiet            only the summary (output of failed examples is shown)
#   examples/examples.sh --list             list the cases and exit
#
# Needs what the repository's ./compile.sh and ./envverify.sh set up: the Rust binary in
# rust/target/release, Node.js, and for the Bash variants bash >= 4 with OpenSSL >= 3.2.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1

langs="rust ts bash"
quiet=0
list=0
filters=()
while (($#)); do
  case "$1" in
    --lang)
      [[ $# -ge 2 ]] || { echo "examples.sh: --lang needs a value, e.g. --lang rust,ts" >&2; exit 1; }
      langs="${2//,/ }"
      shift
      ;;
    --quiet) quiet=1 ;;
    --list) list=1 ;;
    -h | --help)
      sed -n '2,13p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    -*)
      echo "examples.sh: unknown option $1 (see --help)" >&2
      exit 1
      ;;
    *) filters+=("$1") ;;
  esac
  shift
done
for lang in $langs; do
  case "$lang" in
    rust | ts | bash) ;;
    *) echo "examples.sh: unknown variant '$lang': use rust, ts or bash" >&2; exit 1 ;;
  esac
done

cases=()
for dir in case-*/; do
  dir="${dir%/}"
  if ((${#filters[@]})); then
    keep=0
    for filter in "${filters[@]}"; do
      [[ "$dir" == *"$filter"* ]] && keep=1
    done
    ((keep)) || continue
  fi
  cases+=("$dir")
done
if ((${#cases[@]} == 0)); then
  echo "examples.sh: no case matches: ${filters[*]}" >&2
  exit 1
fi
if ((list)); then
  printf '%s\n' "${cases[@]}"
  exit 0
fi

# Milliseconds since the epoch (bash 3.2 has no built-in clock with fractions).
now_ms() { perl -MTime::HiRes=time -e 'printf "%d", time * 1000'; }

# Milliseconds as a duration a person reads at a glance: 340ms, 4.2s, 1m 07s, 1h 02m 03s.
human() {
  local ms="$1" s
  if ((ms < 1000)); then
    printf '%dms' "$ms"
  elif ((ms < 60000)); then
    printf '%d.%ds' "$((ms / 1000))" "$((ms % 1000 / 100))"
  else
    s=$((ms / 1000))
    if ((s < 3600)); then
      printf '%dm %02ds' "$((s / 60))" "$((s % 60))"
    else
      printf '%dh %02dm %02ds' "$((s / 3600))" "$((s % 3600 / 60))" "$((s % 60))"
    fi
  fi
}

# An interrupted run must not continue with the next example.
trap 'echo; echo "examples.sh: interrupted"; exit 130' INT

# ---------------------------------------------------------------------------------------
# Done once here instead of in every example: check that what the examples call is built,
# and download + build the Rust example programs. The examples then skip these steps
# because SSENC_EXAMPLES_PREPARED is set (see `built` and `run_once` in lib/demo.sh).
# ---------------------------------------------------------------------------------------
root="$(cd .. && pwd)"
need() {
  if [[ ! -e "$1" ]]; then
    echo "examples.sh: CANNOT RUN: $1 does not exist. Build it first: $2" >&2
    exit 4
  fi
}
printf '##### prepare (once for all examples) #####\n'
prepare_started="$(now_ms)"
# Every variant may call the other implementations (case-015), so all three are checked.
need "$root/rust/target/release/ssenc" "rust/compile.sh"
need "$root/typescript/dist/cli.ts" "typescript/compile.sh"
need "$root/typescript/dist/ssenc.node.ts" "typescript/compile.sh"
need "$root/bash/bin/ssenc" "(it is part of the repository)"
echo "ok: the three implementations are present"
case " $langs " in
  *" rust "*)
    for dir in "${cases[@]}"; do
      [[ -d "$dir/rust-app" ]] || continue
      step_started="$(now_ms)"
      if ! "$dir/rust-app/install.sh" || ! "$dir/rust-app/compile.sh"; then
        echo "examples.sh: CANNOT RUN: building $dir/rust-app failed (see the messages above)" >&2
        exit 4
      fi
      echo "ok: built $dir/rust-app ($(human "$(($(now_ms) - step_started))"))"
    done
    ;;
esac
echo "prepare took $(human "$(($(now_ms) - prepare_started))")"
export SSENC_EXAMPLES_PREPARED=1

log="$(mktemp "${TMPDIR:-/tmp}/ssenc-examples.XXXXXX")"
trap 'rm -f "$log"' EXIT
planned=0
for lang in $langs; do planned=$((planned + ${#cases[@]})); done
current=0
results=()
failed=0
started="$(now_ms)"
for dir in "${cases[@]}"; do
  for lang in $langs; do
    script="$dir/$lang.sh"
    current=$((current + 1))
    position="$(printf '%*d of %d' "${#planned}" "$current" "$planned")"
    if [[ ! -x "$script" ]]; then
      results+=("MISSING  $position  $script")
      failed=$((failed + 1))
      continue
    fi
    begin="$(now_ms)"
    if ((quiet)); then
      "./$script" > "$log" 2>&1
      code=$?
      if ((code != 0)); then cat "$log"; fi
    else
      "./$script" 2>&1
      code=$?
    fi
    took="$(human "$(($(now_ms) - begin))")"
    if ((code == 0)); then
      results+=("$(printf 'ok       %s  %-5s %8s  %s' "$position" "$lang" "$took" "$dir")")
    else
      results+=("$(printf 'FAILED   %s  %-5s %8s  %s   (exit code %s; run examples/%s to see it alone)' "$position" "$lang" "$took" "$dir" "$code" "$script")")
      failed=$((failed + 1))
    fi
    if ((!quiet)); then
      if ((code == 0)); then verdict="ok"; else verdict="FAILED, exit code $code"; fi
      printf '\n----- %s: %s, took %s, test %d of %d -----\n' "$script" "$verdict" "$took" "$current" "$planned"
    fi
  done
done

printf '\n##### summary #####\n'
printf '%s\n' "${results[@]}"
total=${#results[@]}
elapsed="$(human "$(($(now_ms) - started))")"
echo
if ((failed)); then
  echo "examples: $failed of $total FAILED (total time $elapsed)"
  exit 1
fi
echo "examples: all $total passed (total time $elapsed)"
