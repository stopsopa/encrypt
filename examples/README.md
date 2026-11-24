# Examples

Runnable demos of every way to use ssenc, from the simplest to the most involved. Each
`case-NNN-…` directory shows one use case three times:

| Script | Uses |
|---|---|
| `rust.sh` | the Rust command (`rust/target/release/ssenc`) or the Rust library |
| `ts.sh` | the TypeScript command run by Node.js (`typescript/bin/ssenc`) or the TypeScript library |
| `bash.sh` | the Bash command (`bash/bin/ssenc`) or the Bash functions (`bash/ssenc.sh`) |

Every script prints each command before it runs it, generates its own demo passwords and
keys, and checks its own results (it stops with a non-zero exit code when something is not
as described).

## Running

```sh
./compile.sh                               # once, in the repository root: builds the Rust binary

examples/case-001-cli_text_with_password/rust.sh    # one example
examples/examples.sh                       # all of them (about 6 minutes), summary at the end
examples/examples.sh 011 ssh               # only cases whose name contains 011 or ssh
examples/examples.sh --lang rust           # only one variant: rust, ts or bash
examples/examples.sh --quiet               # summary only
xx examples                                # the same through the xx menu
```

Needs: the Rust toolchain, Node.js (version in `.tool-versions`), and for the `bash.sh`
variants bash ≥ 4 with OpenSSL ≥ 3.2. `./envverify.sh` in the repository root checks all of
it.

## What is in a case directory

| File | Purpose |
|---|---|
| `prepare.sh` | Creates `tmp/` with the demo password, demo ssh keys and input files. Called by the three scripts; can be run on its own. |
| `rust.sh`, `ts.sh`, `bash.sh` | The example. |
| `demo.ts` | Library cases: the TypeScript program that `ts.sh` runs. |
| `rust-app/` | Library cases: a separate Rust program (`Cargo.toml`, `src/main.rs`, `install.sh`, `compile.sh`) that `rust.sh` builds and runs. |
| `tmp/` | Everything generated. Ignored by git, recreated on every run. |

Examples that use ssh keys start a private `ssh-agent` in `/tmp/ssenc-demo.*` and stop it
when they end. Your own agent is never used: the scripts unset `SSH_AUTH_SOCK` first.

## Command line

| Case | Shows |
|---|---|
| [001](case-001-cli_text_with_password) | Encrypt a text from standard input with a password, decrypt it, heredoc |
| [002](case-002-cli_file_with_password) | Encrypt and decrypt a file, password from a file, in place |
| [003](case-003-cli_binary_file_blob_mode) | Binary file to ASCII text and back (`--mode blob`, `--chunk`); `--mode auto` |
| [004](case-004-cli_inspect_without_key) | `inspect`: mode, settings and key slots without a key |
| [005](case-005-cli_update_changes_only_edited_lines) | Re-encrypt an edited file so that only the edited line changes (`--previous`, `--fresh`) |
| [006](case-006-cli_whitespace_and_padding) | `--no-preserve-ws` and `--pad` |
| [007](case-007-cli_seal_detects_removed_lines) | What tampering is detected, and what `--seal` adds |
| [008](case-008-cli_password_cost_kdf) | The cost of the password step (`--kdf`) |
| [009](case-009-cli_errors_and_exit_codes) | Every exit code and its message |
| [010](case-010-cli_rekey_change_password) | Change the password (`rekey`, `--rewrap-only`) |
| [011](case-011-cli_ssh_key_from_ssh_agent) | An ssh key in `ssh-agent` instead of a password (Ed25519, RSA, by fingerprint) |
| [012](case-012-cli_several_keys_ssh_and_backup_password) | One file for several ssh keys and a backup password |
| [013](case-013-cli_rekey_between_password_and_ssh_key) | Move between password and ssh keys, add and remove keys |
| [014](case-014-cli_many_files_fast_with_random_key) | Many files quickly: random key file and minimum password cost |
| [015](case-015-cli_other_implementations_read_the_same_files) | Files made by one implementation are read, updated and rekeyed by the other two |
| [016](case-016-cli_git_diff_shows_the_edited_line) | In git: one-line diffs, and plain-text diffs through a `textconv` filter |

## Library

| Case | Shows |
|---|---|
| [017](case-017-lib_text_with_password) | Encrypt and decrypt a text; the JavaScript and browser builds |
| [018](case-018-lib_files_text_and_binary) | Text file line by line, binary file as a blob, `inspect`, mode `auto` |
| [019](case-019-lib_options_and_stable_updates) | Every option of `encrypt`; updates that change only the edited lines |
| [020](case-020-lib_errors_by_kind) | Every kind of error and how a program reacts to it |
| [021](case-021-lib_rekey_replace_keys) | `rekey`, with or without a new data key, several new keys |
| [022](case-022-lib_ssh_agent_keys) | ssh keys from `ssh-agent`: by public key, by fingerprint, with a password |
| [023](case-023-lib_ssh_key_with_own_signer) | An ssh key that is not in an agent: your own signer function |
| [024](case-024-lib_many_encryptions_fast) | Many encryptions quickly from a program; the key cache |

Case 023 differs between variants: the TypeScript and Rust libraries accept a signer
function, the Bash library does not, so `bash.sh` shows what Bash can choose instead (which
agent is asked).

## Encoder process on a socket

[`socket/`](socket) is not a case with three variants but one small program: a process that
stays running, listens on a unix socket and encrypts or decrypts the files named in the
requests it receives, with an ssh key (`server.ts`, `client.ts`, `protocol.ts`; each file
starts with a description). How to try it, step by step, and how fast it is: the two
`socket-…` sections at the end of [SUMMARY.md](SUMMARY.md). What it generates goes to
`socket/tmp/`, ignored by git. `examples.sh` does not run it.

## Shared files

- `examples.sh` — runs the cases and prints a summary; exit code 1 when any example failed.
  Before the first example it checks once that the implementations are built and builds
  the `rust-app/` programs, then exports `SSENC_EXAMPLES_PREPARED=1` so the examples skip
  those steps. An example started directly still does them itself.
- `lib/demo.sh` — the helpers the scripts use to print and check: `run`, `timed`, `fails`,
  `check`, `built`, `demo_agent_start`.
- `.target/` — build directory shared by all `rust-app/` programs, so their dependencies
  compile once. Ignored by git.
