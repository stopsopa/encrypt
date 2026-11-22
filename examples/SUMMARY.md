# Examples summary

All commands are run from the repository root. Every case does the same thing three times: with Rust, TypeScript and Bash.

```sh
examples/examples.sh        # all cases, all three variants
```

## case-001-cli_text_with_password

Encrypt a text from standard input with a password, decrypt it, heredoc

```sh
examples/case-001-cli_text_with_password/rust.sh
examples/case-001-cli_text_with_password/ts.sh
examples/case-001-cli_text_with_password/bash.sh
```

## case-002-cli_file_with_password

Encrypt and decrypt a file, password from a file, in place

```sh
examples/case-002-cli_file_with_password/rust.sh
examples/case-002-cli_file_with_password/ts.sh
examples/case-002-cli_file_with_password/bash.sh
```

## case-003-cli_binary_file_blob_mode

Binary file to ASCII text and back (`--mode blob`, `--chunk`)

```sh
examples/case-003-cli_binary_file_blob_mode/rust.sh
examples/case-003-cli_binary_file_blob_mode/ts.sh
examples/case-003-cli_binary_file_blob_mode/bash.sh
```

## case-004-cli_inspect_without_key

`inspect`: mode, settings and key slots without a key

```sh
examples/case-004-cli_inspect_without_key/rust.sh
examples/case-004-cli_inspect_without_key/ts.sh
examples/case-004-cli_inspect_without_key/bash.sh
```

## case-005-cli_update_changes_only_edited_lines

Re-encrypt an edited file so that only the edited line changes (`--previous`, `--fresh`)

```sh
examples/case-005-cli_update_changes_only_edited_lines/rust.sh
examples/case-005-cli_update_changes_only_edited_lines/ts.sh
examples/case-005-cli_update_changes_only_edited_lines/bash.sh
```

## case-006-cli_whitespace_and_padding

`--no-preserve-ws` and `--pad`

```sh
examples/case-006-cli_whitespace_and_padding/rust.sh
examples/case-006-cli_whitespace_and_padding/ts.sh
examples/case-006-cli_whitespace_and_padding/bash.sh
```

## case-007-cli_seal_detects_removed_lines

What tampering is detected, and what `--seal` adds

```sh
examples/case-007-cli_seal_detects_removed_lines/rust.sh
examples/case-007-cli_seal_detects_removed_lines/ts.sh
examples/case-007-cli_seal_detects_removed_lines/bash.sh
```

## case-008-cli_password_cost_kdf

The cost of the password step (`--kdf`)

```sh
examples/case-008-cli_password_cost_kdf/rust.sh
examples/case-008-cli_password_cost_kdf/ts.sh
examples/case-008-cli_password_cost_kdf/bash.sh
```

## case-009-cli_errors_and_exit_codes

Every exit code and its message

```sh
examples/case-009-cli_errors_and_exit_codes/rust.sh
examples/case-009-cli_errors_and_exit_codes/ts.sh
examples/case-009-cli_errors_and_exit_codes/bash.sh
```

## case-010-cli_rekey_change_password

Change the password (`rekey`, `--rewrap-only`)

```sh
examples/case-010-cli_rekey_change_password/rust.sh
examples/case-010-cli_rekey_change_password/ts.sh
examples/case-010-cli_rekey_change_password/bash.sh
```

## case-011-cli_ssh_key_from_ssh_agent

An ssh key in `ssh-agent` instead of a password (Ed25519, RSA, by fingerprint)

```sh
examples/case-011-cli_ssh_key_from_ssh_agent/rust.sh
examples/case-011-cli_ssh_key_from_ssh_agent/ts.sh
examples/case-011-cli_ssh_key_from_ssh_agent/bash.sh
```

## case-012-cli_several_keys_ssh_and_backup_password

One file for several ssh keys and a backup password

```sh
examples/case-012-cli_several_keys_ssh_and_backup_password/rust.sh
examples/case-012-cli_several_keys_ssh_and_backup_password/ts.sh
examples/case-012-cli_several_keys_ssh_and_backup_password/bash.sh
```

## case-013-cli_rekey_between_password_and_ssh_key

Move between password and ssh keys, add and remove keys

```sh
examples/case-013-cli_rekey_between_password_and_ssh_key/rust.sh
examples/case-013-cli_rekey_between_password_and_ssh_key/ts.sh
examples/case-013-cli_rekey_between_password_and_ssh_key/bash.sh
```

## case-014-cli_many_files_fast_with_random_key

Many files quickly: random key file and minimum password cost

```sh
examples/case-014-cli_many_files_fast_with_random_key/rust.sh
examples/case-014-cli_many_files_fast_with_random_key/ts.sh
examples/case-014-cli_many_files_fast_with_random_key/bash.sh
```

## case-015-cli_other_implementations_read_the_same_files

Files made by one implementation are read, updated and rekeyed by the other two

```sh
examples/case-015-cli_other_implementations_read_the_same_files/rust.sh
examples/case-015-cli_other_implementations_read_the_same_files/ts.sh
examples/case-015-cli_other_implementations_read_the_same_files/bash.sh
```

## case-016-cli_git_diff_shows_the_edited_line

In git: one-line diffs, and plain-text diffs through a `textconv` filter

```sh
examples/case-016-cli_git_diff_shows_the_edited_line/rust.sh
examples/case-016-cli_git_diff_shows_the_edited_line/ts.sh
examples/case-016-cli_git_diff_shows_the_edited_line/bash.sh
```

## case-017-lib_text_with_password

Encrypt and decrypt a text; the JavaScript and browser builds

```sh
examples/case-017-lib_text_with_password/rust.sh
examples/case-017-lib_text_with_password/ts.sh
examples/case-017-lib_text_with_password/bash.sh
```

## case-018-lib_files_text_and_binary

Text file line by line, binary file as a blob, `inspect`

```sh
examples/case-018-lib_files_text_and_binary/rust.sh
examples/case-018-lib_files_text_and_binary/ts.sh
examples/case-018-lib_files_text_and_binary/bash.sh
```

## case-019-lib_options_and_stable_updates

Every option of `encrypt`; updates that change only the edited lines

```sh
examples/case-019-lib_options_and_stable_updates/rust.sh
examples/case-019-lib_options_and_stable_updates/ts.sh
examples/case-019-lib_options_and_stable_updates/bash.sh
```

## case-020-lib_errors_by_kind

Every kind of error and how a program reacts to it

```sh
examples/case-020-lib_errors_by_kind/rust.sh
examples/case-020-lib_errors_by_kind/ts.sh
examples/case-020-lib_errors_by_kind/bash.sh
```

## case-021-lib_rekey_replace_keys

`rekey`, with or without a new data key, several new keys

```sh
examples/case-021-lib_rekey_replace_keys/rust.sh
examples/case-021-lib_rekey_replace_keys/ts.sh
examples/case-021-lib_rekey_replace_keys/bash.sh
```

## case-022-lib_ssh_agent_keys

ssh keys from `ssh-agent`: by public key, by fingerprint, with a password

```sh
examples/case-022-lib_ssh_agent_keys/rust.sh
examples/case-022-lib_ssh_agent_keys/ts.sh
examples/case-022-lib_ssh_agent_keys/bash.sh
```

## case-023-lib_ssh_key_with_own_signer

An ssh key that is not in an agent: your own signer function

```sh
examples/case-023-lib_ssh_key_with_own_signer/rust.sh
examples/case-023-lib_ssh_key_with_own_signer/ts.sh
examples/case-023-lib_ssh_key_with_own_signer/bash.sh
```

## case-024-lib_many_encryptions_fast

Many encryptions quickly from a program; the key cache

```sh
examples/case-024-lib_many_encryptions_fast/rust.sh
examples/case-024-lib_many_encryptions_fast/ts.sh
examples/case-024-lib_many_encryptions_fast/bash.sh
```
