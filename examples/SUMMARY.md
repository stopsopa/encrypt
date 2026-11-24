# Examples summary

The essence of every example in a few lines. `$S` stands for any of the three commands
(`rust/target/release/ssenc`, `typescript/bin/ssenc`, `bash/bin/ssenc`): they take the same
arguments. The full, runnable version of each block is in the directory named in the header
(`rust.sh`, `ts.sh`, `bash.sh`).

you can use snippet 

```
export S="rust/target/release/ssenc"
export S="typescript/bin/ssenc"
export S="bash/bin/ssenc"

```

## Synopsis: all arguments

```
$S encrypt KEYS    [--mode lines|blob|auto] [--no-preserve-ws] [--pad N] [--chunk N] [--kdf PROFILE]
                   [--seal] [--previous FILE | --fresh] [-i IN] [-o OUT]
$S decrypt KEY     [-i IN] [-o OUT]
$S rekey   KEY NEWKEYS [--kdf PROFILE] [--rewrap-only] [-i IN] [-o OUT]
$S inspect [-i IN]
$S --version
$S --help
```

The command (`encrypt`, `decrypt`, `rekey`, `inspect`) is always the first argument; the
order of the other arguments does not matter.

| Argument | Used with | Required | Default | Example |
|---|---|---|---|---|
| `encrypt` \| `decrypt` \| `rekey` \| `inspect` | | yes, exactly one | — | [case 001](#case-001-cli_text_with_password) (`encrypt`, `decrypt`), [case 010](#case-010-cli_rekey_change_password) (`rekey`), [case 004](#case-004-cli_inspect_without_key) (`inspect`) |
| `-i FILE` | all four | no | standard input | [case 002](#case-002-cli_file_with_password) |
| `-o FILE` | `encrypt`, `decrypt`, `rekey` | no | standard output | [case 002](#case-002-cli_file_with_password) |
| `--password-file FILE` | `encrypt`, `decrypt`, `rekey` | a key is required, see KEY below | — | [case 002](#case-002-cli_file_with_password) |
| `SSENC_PASSWORD` (environment variable) | `encrypt`, `decrypt`, `rekey` | a key is required, see KEY below | — | [case 001](#case-001-cli_text_with_password) |
| `--ssh-key FILE.pub` \| `--ssh-key SHA256:…` | `encrypt` (any number), `decrypt` and `rekey` (one) | a key is required, see KEY below | — | [case 011](#case-011-cli_ssh_key_from_ssh_agent), [case 012](#case-012-cli_several_keys_ssh_and_backup_password) (several keys) |
| `--new-password-file FILE` | `rekey` | a new key is required, see NEWKEYS below | — | [case 010](#case-010-cli_rekey_change_password) |
| `SSENC_NEW_PASSWORD` (environment variable) | `rekey` | a new key is required, see NEWKEYS below | — | [case 010](#case-010-cli_rekey_change_password) |
| `--new-ssh-key FILE.pub` \| `--new-ssh-key SHA256:…` | `rekey` (any number) | a new key is required, see NEWKEYS below | — | [case 013](#case-013-cli_rekey_between_password_and_ssh_key) |
| `--mode lines\|blob\|auto` | `encrypt` | no | `lines` | [case 003](#case-003-cli_binary_file_blob_mode) |
| `--no-preserve-ws` | `encrypt` | no | off: indentation stays readable | [case 006](#case-006-cli_whitespace_and_padding) |
| `--pad N` | `encrypt` | no | `16` | [case 006](#case-006-cli_whitespace_and_padding) |
| `--chunk N` | `encrypt` | no | `65536` | [case 003](#case-003-cli_binary_file_blob_mode) |
| `--kdf PROFILE` | `encrypt`, `rekey` | no | `default` (= `m=65536,t=3,p=4`) | [case 008](#case-008-cli_password_cost_kdf) |
| `--seal` | `encrypt` | no | off | [case 007](#case-007-cli_seal_detects_removed_lines) |
| `--previous FILE` | `encrypt` | no | the `-o` file, when it exists and is an encrypted file | [case 005](#case-005-cli_update_changes_only_edited_lines) |
| `--fresh` | `encrypt` | no | off | [case 005](#case-005-cli_update_changes_only_edited_lines) |
| `--rewrap-only` | `rekey` | no | off: everything is encrypted again | [case 010](#case-010-cli_rekey_change_password) |
| `--version` | alone | no | — | — |
| `--help`, `-h` | alone | no | — | — |

The defaults of `--mode`, `--no-preserve-ws`, `--pad`, `--chunk` and `--seal` are for a new
file. When the `-o` file already exists and is an encrypted file (or `--previous` is given),
what is not given on the command line is taken from that file. `--fresh` brings the defaults
back.

What each one does:

- **`encrypt`**: plain input to encrypted ASCII text.
- **`decrypt`**: encrypted text back to the original bytes. Takes no options about the
  format: everything needed is written in the file.
- **`rekey`**: replaces the keys of an encrypted file. All old keys stop working.
- **`inspect`**: prints one line of JSON saying how a file was encrypted (mode, settings,
  key slots). Needs no key.
- **`-i FILE`**: where the input is read from. The whole input is read before anything is
  written, so `-i` and `-o` may name the same file.
- **`-o FILE`**: where the result is written. Nothing is written when there is an error.
  `inspect` always prints to standard output.
- **KEY** (required for `encrypt`, `decrypt`, `rekey`): the first one found of
  `--password-file`, then `SSENC_PASSWORD`. When neither is given and there is no
  `--ssh-key`, the password is asked for on the terminal, but only when `-i` names a file
  and the terminal is interactive; otherwise it is an error (exit code 1).
  - **`--password-file FILE`**: the password is the content of FILE, without one newline at
    its end. A password is never taken as an argument, because other processes can see
    arguments.
  - **`SSENC_PASSWORD`**: the password itself.
  - **`--ssh-key`**: an ssh key instead of (or, for `encrypt`, in addition to) a password,
    named by its public key file or by its fingerprint. Its private key has to be loaded in
    `ssh-agent`. `encrypt` takes a password and any number of `--ssh-key` at once, and each
    of them alone opens the file later. `decrypt` and `rekey` use one key: `--ssh-key` when
    given, otherwise the password.
- **NEWKEYS** (required for `rekey`, at least one): the keys the file has afterwards.
  `--new-password-file` (or else `SSENC_NEW_PASSWORD`) and any number of `--new-ssh-key`,
  written like the ones above. There is no prompt for a new password.
- **`--mode`**: `lines`: every line of the input becomes one encrypted line, so an edit of
  one line changes one line. `blob`: the input is encrypted as a whole, for binary files or
  when the line structure must not show. `auto`: `lines` when the input is text (no NUL
  byte, valid UTF-8), otherwise `blob`.
- **`--no-preserve-ws`**: lines mode only. Normally the spaces and tabs at the beginning
  and the end of each line stay as they are, so indentation is readable in the encrypted
  file. With this option they are encrypted too. Ignored in blob mode.
- **`--pad N`**: lines mode only. Each line is filled up to a multiple of N bytes before it
  is encrypted, so the exact length of a line does not show. `0` switches it off; the
  highest value is 4096. Ignored in blob mode.
- **`--chunk N`**: blob mode only. The size in bytes of the pieces the input is cut into,
  from 1 to 1048576 (explained in case 003). Ignored in lines mode.
- **`--kdf PROFILE`**: how much work it takes to turn the password into a key, which is
  what slows down someone guessing passwords. `default`: 64 MiB of memory, 3 passes.
  `strong`: 1 GiB, 4 passes. Or exact values: `m=<KiB>,t=<passes>,p=<lanes>`. Has no effect
  on ssh keys, and none when the key lines are copied from an existing file.
- **`--seal`**: lines mode only. Adds a `#seal` line with a checksum over the whole file at its top,
  so that removed, added or moved lines are detected (a changed line is always detected). In
  blob mode it is an error (exit code 1): a blob is protected like that already.
- **`--previous FILE`**: use the data key of an earlier encrypted version, so lines that
  were not edited stay identical (explained in case 005).
- **`--fresh`**: do not use the existing `-o` file as `--previous` (explained in case 005).
  Cannot be combined with `--previous`.
- **`--rewrap-only`**: `rekey` replaces only the key lines at the top and leaves the rest
  of the file byte for byte as it was. Faster and with a small diff, but someone who has an
  old key and an old copy of the file can still read later versions.
- **`--version`**: prints the implementation and the version, e.g. `ssenc rust 0.1.0`.
- **`--help`**, **`-h`**: prints the usage.

## case-001-cli_text_with_password

Encrypt a text from standard input with a password and decrypt it.

```sh
export SSENC_PASSWORD="$(openssl rand -base64 24)"
echo "${SSENC_PASSWORD=}"

echo "my first secret" | $S encrypt > s/secret.enc
$S decrypt < s/secret.enc                      # my first secret
```

## case-002-cli_file_with_password

Encrypt and decrypt a file; the password is read from a file.

```sh
openssl rand -base64 24 > s/password.txt

$S encrypt --password-file s/password.txt -i xx.ts      -o s/xx.ts.enc
$S decrypt --password-file s/password.txt -i s/xx.ts.enc  -o s/xx.ts.decoded
diff xx.ts s/xx.ts.decoded 
$S decrypt --password-file s/password.txt -i s/xx.ts.enc      # to standard output

$S encrypt --password-file s/password.txt -i s/xx.ts.decoded -o s/xx.ts.decoded   # in place: same file in and out
$S decrypt --password-file s/password.txt -i s/xx.ts.decoded -o s/xx.ts.decoded 
diff xx.ts s/xx.ts.decoded 
```

## case-003-cli_binary_file_blob_mode

Any bytes (an image, an archive) become ASCII text and come back identical.

```sh
$S encrypt --mode blob --password-file s/password.txt -i s/i.jpg -o s/i.jpg.txt
head -n 4 s/i.jpg.txt
$S decrypt --password-file s/password.txt -i s/i.jpg.txt -o s/i.decoded.jpg   # no --mode: it is in the file
cmp s/i.jpg s/i.decoded.jpg && echo identical
ls -la s/i*
```

What `--chunk 16384` does: blob mode does not lock the whole file as one piece. It cuts the
file into pieces of a fixed size and locks each piece separately, each with its own tamper
seal. `--chunk 16384` sets that piece size to 16384 bytes (16 KiB) instead of the default
65536 (64 KiB).

- **The 20 KB image `s/i.jpg`:** with the default it is one piece; with `--chunk 16384` it is two.
- **Security:** the same. Every piece is sealed, and their order and count are checked too.
- **Size:** each piece adds 16 bytes for its seal, so smaller pieces make the file slightly bigger.
- **Diffs:** this is the only practical reason to change it. If a few bytes of a binary file
  are overwritten in place, only the pieces containing them change in the encrypted text, so
  smaller pieces give smaller git diffs. If bytes are inserted or removed, everything after
  that point shifts and changes anyway.
- **Decrypting:** needs no option; the piece size is written in the first line of the file
  (`#ssenc1 blob chunk=16384`).

For most files the default is fine.

```sh
$S encrypt --mode blob --chunk 16384 --password-file s/password.txt -i s/i.jpg -o s/i.chunk.txt
$S inspect -i s/i.jpg.txt | jq
$S inspect -i s/i.chunk.txt | jq
```

`--mode auto` decides by itself: lines for text (no NUL byte, valid UTF-8), blob for anything else.

```sh
rm -f s/auto.jpg.txt s/auto.txt.enc
$S encrypt --mode auto --password-file s/password.txt -i s/i.jpg -o s/auto.jpg.txt
head -n 1 s/auto.jpg.txt                        # #ssenc1 blob chunk=65536
$S inspect -i s/auto.jpg.txt | jq

printf "line one\nline two\n" > s/auto.txt
$S encrypt --mode auto --password-file s/password.txt -i s/auto.txt -o s/auto.txt.enc
head -n 1 s/auto.txt.enc                        # #ssenc1 lines ws=1 pad=16
$S inspect -i s/auto.txt.enc | jq

# an existing output file keeps its mode, whatever the new content is ...
cp s/auto.txt.enc s/auto.v1.enc
printf "line one\nline \377 two\n" > s/auto.txt
$S encrypt --mode auto --password-file s/password.txt -i s/auto.txt -o s/auto.txt.enc
diff s/auto.v1.enc s/auto.txt.enc               # still lines, and only one line changed

# ... unless --fresh starts over
$S encrypt --mode auto --fresh --password-file s/password.txt -i s/auto.txt -o s/auto.txt.enc
head -n 1 s/auto.txt.enc                        # #ssenc1 blob chunk=65536
```

## case-004-cli_inspect_without_key

See how a file was encrypted, without having the key.

```sh
printf "line one\nline two\n" > s/notes.txt
$S encrypt --fresh --password-file s/password.txt -i s/notes.txt -o s/notes.txt.enc

$S inspect -i s/notes.txt.enc | jq
# {"format":"ssenc1","mode":"lines","ws":true,"pad":16,"seal":false,"slots":[{"type":"pw","kdf":"argon2id","m":65536,"t":3,"p":4}]}

$S inspect -i s/notes.txt; echo "exit code $?"     # not an encrypted file: exit code 3
$S --version
```

## case-005-cli_update_changes_only_edited_lines

After an edit of the plain file, only the edited line changes in the encrypted file.

```sh
printf "host: db.internal\nport: 5432\nuser: admin\n" > s/config.yml
$S encrypt --fresh --password-file s/password.txt -i s/config.yml -o s/config.yml.enc   # first time
cp s/config.yml.enc s/config.v1.enc

printf "host: db.internal\nport: 6543\nuser: admin\n" > s/config.yml                    # edit one line
$S encrypt --password-file s/password.txt -i s/config.yml -o s/config.yml.enc           # existing output is reused
diff s/config.v1.enc s/config.yml.enc                                                   # one line differs
```

What `--previous FILE` does: every encrypted file has its own random **data key**, the key
that really locks the lines. It is stored in the `#slot` line at the top, itself locked with
your password. The same line locked with the same data key always gives the same encrypted
text. Normally `encrypt` makes a new data key every time, so every line comes out different
even when nothing was edited. `--previous FILE` means: open FILE with my key, take its data
key and use it again.

- **Result:** lines that were not edited come out exactly as they are in FILE; only edited
  lines differ. Nothing is compared: it follows from using the same data key.
- **FILE is only read.** The result goes to `-o` (or standard output).
- **The top of the file is copied:** the `#slot` lines are taken from FILE as they are, and
  the settings of the first line (mode, `ws`, `pad`) too, unless given on the command line.
  `--kdf` has no effect, because no new `#slot` line is made.
- **Your key must open FILE.** If it does not: exit code 2, nothing is written.
- **Writing to an existing output file is the same thing:** the command above used
  `s/config.yml.enc` itself as FILE, without being asked. `--fresh` switches that off.
- **When to give it yourself:** when the earlier version is somewhere else than the output:
  the output goes to standard output or to a new name, or the earlier version comes from git
  (`git show HEAD:config.yml.enc > s/old.enc`).

```sh
# reuse another file than the output
$S encrypt --password-file s/password.txt --previous s/config.v1.enc -i s/config.yml -o s/config.other.enc
diff s/config.v1.enc s/config.other.enc                                                 # the same one line
```

**TLDR: `--fresh` makes a difference only when the `-o` file already exists and is an
encrypted file.** In every other case (no such file yet, a file that is not an encrypted
one, output to standard output) the result is the same with and without it.

What `--fresh` does: it tells `encrypt` to ignore the file that already exists at `-o` and
to overwrite it as if it was not there.

| When `-o` is an existing encrypted file | without `--fresh` | with `--fresh` |
|---|---|---|
| Data key | taken from the existing file | new, random |
| Lines that were not edited | stay identical | change, like every other line |
| `#slot` lines | copied | made again |
| Settings (mode, `pad`, …) | as in the existing file, unless given | from the command line, else the defaults |
| `--kdf` | no effect | used |
| `--mode auto` | the mode of the existing file | detected again |
| Key that does not open the existing file | exit code 2, nothing written | fine: the file is replaced |

Use it to start over with another password or other settings, or to hide which lines were
edited. This document also uses it wherever a block has to work when it is run again after
`s/password.txt` was generated again. `--fresh` and `--previous` cannot be given together.

```sh
# start over: every line changes
$S encrypt --fresh --password-file s/password.txt -i s/config.yml -o s/config.yml.enc
diff s/config.v1.enc s/config.yml.enc
```

## case-006-cli_whitespace_and_padding

What stays visible in an encrypted line: indentation and rough length.

```sh
printf "server:\n    host: db.internal\n    description: a much longer line than the other ones in this file\n" > s/app.yml

$S encrypt --password-file s/password.txt -i s/app.yml                    # indentation stays visible
$S encrypt --no-preserve-ws --password-file s/password.txt -i s/app.yml   # indentation is encrypted too
$S encrypt --pad 0 --password-file s/password.txt -i s/app.yml            # no padding: exact line lengths show
$S encrypt --pad 128 --password-file s/password.txt -i s/app.yml          # all lines look the same length
```

## case-007-cli_seal_detects_removed_lines

A changed line is always detected; a removed or moved line only with `--seal`.

```sh
printf "allow alice\nallow bob\ndeny mallory\nallow carol\n" > s/rules.txt

$S encrypt --fresh --password-file s/password.txt -i s/rules.txt -o s/rules.enc
sed "5d" s/rules.enc | $S decrypt --password-file s/password.txt                       # works: "deny mallory" is silently missing

$S encrypt --fresh --seal --password-file s/password.txt -i s/rules.txt -o s/sealed.enc
sed "6d" s/sealed.enc | $S decrypt --password-file s/password.txt; echo "exit code $?"   # exit code 2

# a changed line is detected with or without the seal
sed "5s/./x/" s/rules.enc | $S decrypt --password-file s/password.txt; echo "exit code $?"   # exit code 2
```

## case-008-cli_password_cost_kdf

How expensive it is to turn the password into a key (and so to guess it).

```sh
echo "the launch code is 0000" > s/secret.txt

time $S encrypt --fresh --password-file s/password.txt -i s/secret.txt -o s/secret.enc                        # default: 64 MiB, 3 passes
time $S encrypt --fresh --kdf strong --password-file s/password.txt -i s/secret.txt -o s/secret.enc           # 1 GiB, 4 passes (typescript: half a minute)
time $S encrypt --fresh --kdf m=19456,t=2,p=1 --password-file s/password.txt -i s/secret.txt -o s/secret.enc  # your own numbers

$S inspect -i s/secret.enc                                   # the cost is stored in the file ...
$S decrypt --password-file s/password.txt -i s/secret.enc    # ... so decrypt needs no option
```

## case-009-cli_errors_and_exit_codes

Every kind of failure has its own exit code.

```sh
echo "the launch code is 0000" > s/secret.txt
$S encrypt --fresh --password-file s/password.txt -i s/secret.txt -o s/secret.enc
rm -f s/unloaded s/unloaded.pub
ssh-keygen -q -t ed25519 -N "" -f s/unloaded       # an ssh key that is in no agent

$S decrypt --password-file s/password.txt -i s/secret.enc; echo "exit code $?"                 # 0
SSENC_PASSWORD="wrong" $S decrypt -i s/secret.enc; echo "exit code $?"                         # 2  AUTH: wrong key, or the file was modified
echo "just some text" | $S decrypt --password-file s/password.txt; echo "exit code $?"         # 3  MALFORMED: not an ssenc file
$S decrypt --no-such-option -i s/secret.enc; echo "exit code $?"                               # 1  USAGE: bad arguments, empty or missing password
SSH_AUTH_SOCK= $S encrypt --ssh-key s/unloaded.pub -i s/secret.txt; echo "exit code $?"        # 4  ENV: no ssh-agent, or the key is not in it

$S decrypt --password-file s/nothing.txt -i s/secret.enc -o s/secret.out || echo "failed with $?"
```

## case-010-cli_rekey_change_password

Change the password of an encrypted file.

```sh
printf "host: db.internal\nport: 5432\n" > s/rekey.yml
echo "old password" > s/old.txt
echo "new password" > s/new.txt
$S encrypt --fresh --password-file s/old.txt -i s/rekey.yml -o s/rekey.enc

$S rekey --password-file s/old.txt --new-password-file s/new.txt -i s/rekey.enc -o s/rekey.enc
$S decrypt --password-file s/new.txt -i s/rekey.enc
$S decrypt --password-file s/old.txt -i s/rekey.enc; echo "exit code $?"     # 2: the old password is out

# the same with environment variables (here: back to the old password)
SSENC_PASSWORD="new password" SSENC_NEW_PASSWORD="old password" $S rekey -i s/rekey.enc -o s/rekey.enc

# only the key line at the top changes, the rest of the file stays byte-identical
cp s/rekey.enc s/rekey.before.enc
$S rekey --rewrap-only --password-file s/old.txt --new-password-file s/new.txt -i s/rekey.enc -o s/rekey.enc
diff s/rekey.before.enc s/rekey.enc
```

## case-011-cli_ssh_key_from_ssh_agent

An ssh key instead of a password. The private key stays in `ssh-agent`.

Once per terminal: a private agent and two demo keys, all in `s/`. Cases 012, 013, 015 and
022 use them too. Your own agent and keys are not touched; `SSH_AUTH_SOCK` of this terminal
points to the private agent until the clean up at the end of this file.

```sh
unset SSENC_PASSWORD                                  # from case-001; it would be added as one more key
rm -f s/alice s/alice.pub s/bob s/bob.pub
ssh-keygen -q -t ed25519 -N "" -C alice -f s/alice
ssh-keygen -q -t rsa     -N "" -C bob   -f s/bob
eval "$(ssh-agent -a "$PWD/s/agent.sock")"
ssh-add s/alice s/bob
ssh-add -l
```

```sh
printf "API_KEY=8f2c1d\nDB_PASSWORD=hunter2\n" > s/secrets.env

$S encrypt --fresh --ssh-key s/alice.pub -i s/secrets.env -o s/secrets.env.enc
head -n 2 s/secrets.env.enc
$S decrypt --ssh-key s/alice.pub -i s/secrets.env.enc

# the key named by fingerprint (ssh-add -l)
$S decrypt --ssh-key "$(ssh-keygen -lf s/alice.pub | cut -d " " -f 2)" -i s/secrets.env.enc

# an RSA key works the same way
$S encrypt --fresh --ssh-key s/bob.pub -i s/secrets.env -o s/secrets.rsa.enc
$S decrypt --ssh-key s/bob.pub -i s/secrets.rsa.enc
```

## case-012-cli_several_keys_ssh_and_backup_password

One file that several people can open, plus a backup password. Needs the agent of case-011.

```sh
printf "API_KEY=8f2c1d\nDB_PASSWORD=hunter2\n" > s/shared.env
echo "backup password" > s/backup.txt

$S encrypt --fresh --ssh-key s/alice.pub --ssh-key s/bob.pub --password-file s/backup.txt -i s/shared.env -o s/shared.env.enc
$S inspect -i s/shared.env.enc                                    # three slots

$S decrypt --ssh-key s/alice.pub -i s/shared.env.enc              # any one of the three opens it
$S decrypt --ssh-key s/bob.pub -i s/shared.env.enc
$S decrypt --password-file s/backup.txt -i s/shared.env.enc

# an update made with one key keeps all three keys
printf "API_KEY=8f2c1d\nDB_PASSWORD=changed\n" > s/shared.env
$S encrypt --ssh-key s/bob.pub -i s/shared.env -o s/shared.env.enc
$S inspect -i s/shared.env.enc                                    # still three slots
$S decrypt --ssh-key s/alice.pub -i s/shared.env.enc
```

## case-013-cli_rekey_between_password_and_ssh_key

Move a file from a password to an ssh key and back; add and remove keys. Needs the agent of case-011.

```sh
printf "API_KEY=8f2c1d\nDB_PASSWORD=hunter2\n" > s/move.env
echo "backup password" > s/backup.txt
$S encrypt --fresh --password-file s/password.txt -i s/move.env -o s/move.env.enc

# password -> ssh key
$S rekey --password-file s/password.txt --new-ssh-key s/alice.pub -i s/move.env.enc -o s/move.env.enc
$S inspect -i s/move.env.enc

# add keys: list every key the file should have from now on
$S rekey --ssh-key s/alice.pub --new-ssh-key s/alice.pub --new-ssh-key s/bob.pub --new-password-file s/backup.txt -i s/move.env.enc -o s/move.env.enc
$S inspect -i s/move.env.enc

# remove a key: leave it out
$S rekey --ssh-key s/alice.pub --new-ssh-key s/alice.pub -i s/move.env.enc -o s/move.env.enc
$S inspect -i s/move.env.enc

# ssh key -> password
$S rekey --ssh-key s/alice.pub --new-password-file s/password.txt -i s/move.env.enc -o s/move.env.enc
$S decrypt --password-file s/password.txt -i s/move.env.enc
```

## case-014-cli_many_files_fast_with_random_key

Many files quickly: a random key file instead of a human password, and the minimum password cost.

```sh
openssl rand -base64 32 > s/bulk.key       # 256 random bits: nothing to guess, so the cost can be minimal
rm -rf s/plain s/encrypted && mkdir -p s/plain s/encrypted
for i in 1 2 3 4 5 6 7 8; do printf "file $i\nsecret: $RANDOM\n" > s/plain/$i.txt; done

for f in s/plain/*.txt; do
  $S encrypt --kdf m=8,t=1,p=1 --password-file s/bulk.key -i "$f" -o "s/encrypted/$(basename "$f").enc"
done

# in parallel, 4 at a time
ls s/plain | xargs -P 4 -I {} $S encrypt --kdf m=8,t=1,p=1 --password-file s/bulk.key -i s/plain/{} -o s/encrypted/{}.enc

ls s/encrypted
$S decrypt --password-file s/bulk.key -i s/encrypted/3.txt.enc
```

Never use `--kdf m=8,t=1,p=1` with a password a person chose.

## case-015-cli_other_implementations_read_the_same_files

A file made by one implementation is read, updated and rekeyed by the other two. Needs the agent of case-011.

```sh
printf "host: db.internal\nport: 5432\nuser: admin\n" > s/cross.yml

rust/target/release/ssenc encrypt --fresh --password-file s/password.txt -i s/cross.yml -o s/cross.yml.enc
typescript/bin/ssenc      decrypt --password-file s/password.txt -i s/cross.yml.enc
bash/bin/ssenc            decrypt --password-file s/password.txt -i s/cross.yml.enc

cp s/cross.yml.enc s/cross.v1.enc
printf "host: db.internal\nport: 6543\nuser: admin\n" > s/cross.yml                                  # edit one line
typescript/bin/ssenc      encrypt --password-file s/password.txt -i s/cross.yml -o s/cross.yml.enc
diff s/cross.v1.enc s/cross.yml.enc                                                                  # still a one-line diff

bash/bin/ssenc            rekey --password-file s/password.txt --new-ssh-key s/alice.pub -i s/cross.yml.enc -o s/cross.yml.enc
rust/target/release/ssenc decrypt --ssh-key s/alice.pub -i s/cross.yml.enc
```

## case-016-cli_git_diff_shows_the_edited_line

Keep the encrypted file in git; let git show diffs of the plain text. The repository is a throwaway one in `s/repo`.

```sh
rm -rf s/repo && git init -q s/repo
echo "settings.yml" > s/repo/.gitignore            # the plain file is never committed
printf "theme: dark\nlang: en\ntoken: 8f2c1d\n" > s/repo/settings.yml
$S encrypt --password-file s/password.txt -i s/repo/settings.yml -o s/repo/settings.yml.enc
git -C s/repo add .gitignore settings.yml.enc
git -C s/repo -c commit.gpgsign=false commit -q -m "settings, encrypted"

printf "theme: dark\nlang: pl\ntoken: 8f2c1d\n" > s/repo/settings.yml          # edit one line, encrypt again
$S encrypt --password-file s/password.txt -i s/repo/settings.yml -o s/repo/settings.yml.enc
git -C s/repo --no-pager diff                      # one encrypted line differs

# show the plain text in diffs instead
echo "*.enc diff=ssenc" > s/repo/.gitattributes
git -C s/repo config diff.ssenc.textconv "$PWD/$S decrypt --password-file $PWD/s/password.txt -i"
git -C s/repo --no-pager diff                      # -lang: en  +lang: pl
```

## Library cases: how to run them

Cases 017 to 024 use the libraries, so there is no `$S`. Each block writes a small program
into `s/` and runs it from the repository root:

- TypeScript: `s/demo.ts`, run by `node` (it runs `.ts` files directly).
- Rust: `s/app/src/main.rs`, a separate program that uses the crate in `rust/`. Create it once
  with the block below; the first `cargo run` compiles the dependencies (about half a minute).
- Bash: `s/demo.sh`, run by `bash` (the library needs bash ≥ 4, so it is not sourced into zsh).

```sh
mkdir -p s/app/src
cat > s/app/Cargo.toml <<'EOF'
[package]
name = "demo"
version = "0.0.0"
edition = "2021"

[dependencies]
ssenc = { path = "../../rust" }
EOF
```

## case-017-lib_text_with_password

The library: encrypt and decrypt a text.

```sh
cat > s/demo.ts <<'EOF'
import { encrypt, decrypt, decryptToString } from "../typescript/dist/ssenc.node.ts";   // also: ssenc.node.js, ssenc.browser.js

const key = { type: "password", password: "correct horse battery staple" } as const;
const encrypted: string = await encrypt("user: admin\npassword: hunter2\n", key);
const bytes: Uint8Array = await decrypt(encrypted, key);
const text: string = await decryptToString(encrypted, key);

console.log(encrypted);
console.log(bytes);
console.log(text);
EOF
node s/demo.ts
```

```sh
cat > s/app/src/main.rs <<'EOF'
use ssenc::{decrypt, encrypt, EncryptOptions, Key};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = Key::password("correct horse battery staple");
    let encrypted: String = encrypt(b"user: admin\npassword: hunter2\n", &[key.clone()], &EncryptOptions::default())?;
    let bytes: Vec<u8> = decrypt(encrypted.as_bytes(), &key)?;

    println!("{encrypted}");
    println!("{}", String::from_utf8(bytes)?);
    Ok(())
}
EOF
cargo run -q --manifest-path s/app/Cargo.toml
```

```sh
cat > s/demo.sh <<'EOF'
source bash/ssenc.sh
export SSENC_PASSWORD="correct horse battery staple"

encrypted="$(printf "user: admin\npassword: hunter2\n" | ssenc_encrypt)"
echo "$encrypted"
echo "$encrypted" | ssenc_decrypt
EOF
bash s/demo.sh
```

## case-018-lib_files_text_and_binary

Text file line by line, binary file as a blob, `inspect`, mode `auto`.

```sh
printf "host: db.internal\nport: 5432\nuser: admin\n" > s/lib.yml      # the text file of the three programs below
```

```sh
cat > s/demo.ts <<'EOF'
import { readFileSync, writeFileSync } from "node:fs";
import { encrypt, decrypt, inspect, detectMode } from "../typescript/dist/ssenc.node.ts";

const key = { type: "password", password: readFileSync("s/password.txt", "utf8").trim() } as const;

const config = await encrypt(readFileSync("s/lib.yml"), key);                     // lines mode
const photo = await encrypt(readFileSync("s/i.jpg"), key, { mode: "blob" });      // any bytes
const small = await encrypt(readFileSync("s/i.jpg"), key, { mode: "blob", chunk: 4096 });
writeFileSync("s/lib.jpg.enc", photo);

console.log(inspect(config));
console.log(inspect(photo));                 // { format, mode, chunk, slots, ... } without a key
console.log(inspect(small));
const back: Uint8Array = await decrypt(photo, key);
console.log("identical:", Buffer.from(back).equals(readFileSync("s/i.jpg")));

console.log(detectMode(readFileSync("s/i.jpg")), detectMode(readFileSync("s/lib.yml")));   // blob lines
const auto = await encrypt(readFileSync("s/lib.yml"), key, { mode: "auto" });               // lines: it is text
const next = await encrypt(readFileSync("s/i.jpg"), key, { mode: "auto", previous: auto }); // keeps the mode of `auto`
console.log(inspect(auto).mode, inspect(next).mode);                                        // lines lines
EOF
node s/demo.ts
```

```sh
cat > s/app/src/main.rs <<'EOF'
use ssenc::{decrypt, detect_mode, encrypt, inspect, EncryptOptions, Key, Mode};
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = Key::password(fs::read_to_string("s/password.txt")?.trim());

    let config = encrypt(&fs::read("s/lib.yml")?, &[key.clone()], &EncryptOptions::default())?;   // lines mode
    let blob = EncryptOptions { mode: Some(Mode::Blob), ..Default::default() };
    let photo = encrypt(&fs::read("s/i.jpg")?, &[key.clone()], &blob)?;                           // any bytes
    fs::write("s/lib.jpg.enc", &photo)?;

    println!("{}", inspect(config.as_bytes())?.to_json());
    println!("{}", inspect(photo.as_bytes())?.to_json());
    let back = decrypt(photo.as_bytes(), &key)?;
    println!("identical: {}", back == fs::read("s/i.jpg")?);

    assert_eq!(detect_mode(&fs::read("s/i.jpg")?), Mode::Blob);
    let auto = EncryptOptions { mode: Some(Mode::Auto), ..Default::default() };
    let config = encrypt(&fs::read("s/lib.yml")?, &[key.clone()], &auto)?;                        // lines: it is text
    println!("{}", config.lines().next().unwrap());
    Ok(())
}
EOF
cargo run -q --manifest-path s/app/Cargo.toml
```

```sh
cat > s/demo.sh <<'EOF'
source bash/ssenc.sh

ssenc_encrypt --fresh --mode blob --password-file s/password.txt -i s/i.jpg -o s/lib.jpg.enc
ssenc_inspect -i s/lib.jpg.enc
ssenc_decrypt --password-file s/password.txt -i s/lib.jpg.enc -o s/lib.decoded.jpg
cmp s/i.jpg s/lib.decoded.jpg && echo identical

ssenc_encrypt --fresh --mode auto --password-file s/password.txt -i s/lib.yml -o s/lib.yml.enc   # lines: it is text
ssenc_inspect -i s/lib.yml.enc
EOF
bash s/demo.sh
```

## case-019-lib_options_and_stable_updates

Every option of `encrypt`; updates that change only the edited lines.

```sh
cat > s/demo.ts <<'EOF'
import { encrypt } from "../typescript/dist/ssenc.node.ts";

const key = { type: "password", password: "correct horse battery staple" } as const;
const plain = "server:\n    host: db.internal\n    port: 5432\n";
const edited = "server:\n    host: db.internal\n    port: 6543\n";

console.log(await encrypt(plain, key, { kdf: { m: 19456, t: 2, p: 1 } }));   // or "default", "strong", "m=19456,t=2,p=1"
console.log(await encrypt(plain, key, { preserveWhitespace: false }));
console.log(await encrypt(plain, key, { pad: 64 }));
console.log(await encrypt(plain, key, { seal: true }));

const v1 = await encrypt(plain, key);
const v2 = await encrypt(edited, key, { previous: v1 });        // only the edited lines differ from v1
console.log(v1);
console.log(v2);
EOF
node s/demo.ts
```

```sh
cat > s/app/src/main.rs <<'EOF'
use ssenc::{encrypt, EncryptOptions, Key};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = Key::password("correct horse battery staple");
    let plain = b"server:\n    host: db.internal\n    port: 5432\n";
    let edited = b"server:\n    host: db.internal\n    port: 6543\n";

    let options = EncryptOptions {
        kdf: Some("m=19456,t=2,p=1".into()),
        preserve_whitespace: Some(false),
        pad: Some(64),
        seal: Some(true),
        ..Default::default()
    };
    println!("{}", encrypt(plain, &[key.clone()], &options)?);

    let v1 = encrypt(plain, &[key.clone()], &EncryptOptions::default())?;
    let update = EncryptOptions { previous: Some(v1.clone().into_bytes()), ..Default::default() };
    let v2 = encrypt(edited, &[key.clone()], &update)?;             // only the edited lines differ from v1
    println!("{v1}\n{v2}");
    Ok(())
}
EOF
cargo run -q --manifest-path s/app/Cargo.toml
```

```sh
cat > s/demo.sh <<'EOF'
source bash/ssenc.sh
export SSENC_PASSWORD="correct horse battery staple"
printf "server:\n    host: db.internal\n    port: 5432\n" > s/opt.yml
printf "server:\n    host: db.internal\n    port: 6543\n" > s/opt.edited.yml

ssenc_encrypt --kdf m=19456,t=2,p=1 --no-preserve-ws --pad 64 --seal -i s/opt.yml

ssenc_encrypt --fresh -i s/opt.yml -o s/opt.v1.enc
ssenc_encrypt --previous s/opt.v1.enc -i s/opt.edited.yml -o s/opt.v2.enc
diff s/opt.v1.enc s/opt.v2.enc                                  # only the edited line differs
EOF
bash s/demo.sh
```

## case-020-lib_errors_by_kind

Every error has a kind: `USAGE`, `AUTH`, `MALFORMED`, `ENV`.

```sh
cat > s/demo.ts <<'EOF'
import { SsencError, encrypt, decryptToString } from "../typescript/dist/ssenc.node.ts";

async function open(encrypted: string, guess: string): Promise<string | null> {
  try {
    return await decryptToString(encrypted, { type: "password", password: guess });
  } catch (error) {
    if (error instanceof SsencError && error.kind === "AUTH") return null;   // wrong password: ask again
    throw error;                                                             // MALFORMED, USAGE, ENV
  }
}

const encrypted = await encrypt("the launch code is 0000\n", { type: "password", password: "right" });
console.log(await open(encrypted, "wrong"));     // null
console.log(await open(encrypted, "right"));     // the launch code is 0000
await open("just some text", "right").catch((error) => console.log(error.kind, error.message));   // MALFORMED
EOF
node s/demo.ts
```

```sh
cat > s/app/src/main.rs <<'EOF'
use ssenc::{decrypt, encrypt, EncryptOptions, Error, ErrorKind, Key};

fn open(text: &str, guess: &str) -> Result<Option<Vec<u8>>, Error> {
    match decrypt(text.as_bytes(), &Key::password(guess)) {
        Ok(plain) => Ok(Some(plain)),
        Err(error) if error.kind == ErrorKind::Auth => Ok(None),   // wrong password: ask again
        Err(error) => Err(error),                                  // Malformed, Usage, Env
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let encrypted = encrypt(b"the launch code is 0000\n", &[Key::password("right")], &EncryptOptions::default())?;
    println!("{:?}", open(&encrypted, "wrong")?);                  // None
    println!("{:?}", open(&encrypted, "right")?.map(String::from_utf8));
    let error = open("just some text", "right").unwrap_err();
    println!("{:?}: {error}", error.kind);                          // Malformed
    Ok(())
}
EOF
cargo run -q --manifest-path s/app/Cargo.toml
```

```sh
cat > s/demo.sh <<'EOF'
source bash/ssenc.sh
echo "the launch code is 0000" | SSENC_PASSWORD="right" ssenc_encrypt > s/err.enc

for file in s/err.enc s/i.jpg; do
  SSENC_PASSWORD="wrong" ssenc_decrypt -i "$file"
  case $? in
    0) ;;
    2) echo "wrong password, or the file was modified" ;;
    3) echo "not an encrypted file" ;;
    *) echo "usage (1) or environment (4) problem" ;;
  esac
done
EOF
bash s/demo.sh
```

## case-021-lib_rekey_replace_keys

Replace the keys of an encrypted text.

```sh
cat > s/demo.ts <<'EOF'
import { encrypt, decryptToString, rekey, inspect } from "../typescript/dist/ssenc.node.ts";

const oldKey = { type: "password", password: "old password" } as const;
const newKey = { type: "password", password: "new password" } as const;
const thirdKey = { type: "password", password: "third password" } as const;
const encrypted = await encrypt("host: db.internal\nport: 5432\n", oldKey);

const rotated = await rekey(encrypted, oldKey, newKey);                              // everything re-encrypted
const rewrapped = await rekey(encrypted, oldKey, newKey, { rotateDataKey: false });  // only the key line changes
const two = await rekey(encrypted, oldKey, [newKey, thirdKey]);                      // several new keys

console.log(encrypted);
console.log(rotated);
console.log(rewrapped);
console.log(inspect(two).slots.length, "slots");
console.log(await decryptToString(rotated, newKey));
await decryptToString(rotated, oldKey).catch((error) => console.log("old key:", error.kind));   // AUTH
EOF
node s/demo.ts
```

```sh
cat > s/app/src/main.rs <<'EOF'
use ssenc::{decrypt, encrypt, rekey, EncryptOptions, Key, RekeyOptions};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let old_key = Key::password("old password");
    let new_key = Key::password("new password");
    let encrypted = encrypt(b"host: db.internal\nport: 5432\n", &[old_key.clone()], &EncryptOptions::default())?;

    let rotated = rekey(encrypted.as_bytes(), &old_key, &[new_key.clone()], &RekeyOptions::default())?;   // everything re-encrypted
    let rewrap = RekeyOptions { rotate_data_key: false, kdf: None };
    let rewrapped = rekey(encrypted.as_bytes(), &old_key, &[new_key.clone()], &rewrap)?;                  // only the key line changes

    println!("{encrypted}\n{rotated}\n{rewrapped}");
    println!("{}", String::from_utf8(decrypt(rotated.as_bytes(), &new_key)?)?);
    println!("old key: {}", decrypt(rotated.as_bytes(), &old_key).unwrap_err());
    Ok(())
}
EOF
cargo run -q --manifest-path s/app/Cargo.toml
```

```sh
cat > s/demo.sh <<'EOF'
source bash/ssenc.sh
echo "old password" > s/old.txt
echo "new password" > s/new.txt
printf "host: db.internal\nport: 5432\n" | ssenc_encrypt --password-file s/old.txt > s/original.enc

ssenc_rekey --password-file s/old.txt --new-password-file s/new.txt -i s/original.enc -o s/rotated.enc
ssenc_rekey --rewrap-only --password-file s/old.txt --new-password-file s/new.txt -i s/original.enc -o s/rewrapped.enc

diff s/original.enc s/rewrapped.enc                 # only the key line differs
ssenc_decrypt --password-file s/new.txt -i s/rotated.enc
EOF
bash s/demo.sh
```

## case-022-lib_ssh_agent_keys

ssh keys from `ssh-agent`: by public key, by fingerprint, together with a password. Needs the agent of case-011.

```sh
cat > s/demo.ts <<'EOF'
import { readFileSync } from "node:fs";
import { encrypt, decryptToString, sshFingerprint, sshParsePublicKey } from "../typescript/dist/ssenc.node.ts";

const plain = "API_KEY=8f2c1d\nDB_PASSWORD=hunter2\n";
const publicKey = readFileSync("s/alice.pub", "utf8");
const sshKey = { type: "ssh", publicKey } as const;
const otherSshKey = { type: "ssh", publicKey: readFileSync("s/bob.pub", "utf8") } as const;
const backupPassword = { type: "password", password: "backup password" } as const;

const encrypted = await encrypt(plain, sshKey);
console.log(encrypted);
console.log(await decryptToString(encrypted, sshKey));
const fingerprint = await sshFingerprint(sshParsePublicKey(publicKey));                      // "SHA256:..."
console.log(await decryptToString(encrypted, { type: "ssh", fingerprint }));
console.log(await decryptToString(encrypted, { type: "ssh", publicKey, agentSocket: "s/agent.sock" }));

const shared = await encrypt(plain, [sshKey, otherSshKey, backupPassword]);   // any one opens it
console.log(await decryptToString(shared, otherSshKey));
console.log(await decryptToString(shared, backupPassword));
EOF
node s/demo.ts
```

```sh
cat > s/app/src/main.rs <<'EOF'
use ssenc::{decrypt, encrypt, ssh_fingerprint, ssh_parse_public_key, EncryptOptions, Key};
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let plain = b"API_KEY=8f2c1d\nDB_PASSWORD=hunter2\n";
    let public_key = fs::read_to_string("s/alice.pub")?;
    let ssh_key = Key::ssh_public_key(public_key.clone());
    let other_ssh_key = Key::ssh_public_key(fs::read_to_string("s/bob.pub")?);
    let backup_password = Key::password("backup password");

    let encrypted = encrypt(plain, &[ssh_key.clone()], &EncryptOptions::default())?;
    println!("{encrypted}");
    println!("{}", String::from_utf8(decrypt(encrypted.as_bytes(), &ssh_key)?)?);
    let fingerprint = ssh_fingerprint(&ssh_parse_public_key(&public_key)?);             // "SHA256:..."
    println!("{}", String::from_utf8(decrypt(encrypted.as_bytes(), &Key::ssh_fingerprint(fingerprint))?)?);

    let shared = encrypt(plain, &[ssh_key, other_ssh_key.clone(), backup_password.clone()], &EncryptOptions::default())?;
    println!("{}", String::from_utf8(decrypt(shared.as_bytes(), &other_ssh_key)?)?);   // any one opens it
    println!("{}", String::from_utf8(decrypt(shared.as_bytes(), &backup_password)?)?);
    Ok(())
}
EOF
cargo run -q --manifest-path s/app/Cargo.toml
```

```sh
cat > s/demo.sh <<'EOF'
source bash/ssenc.sh
printf "API_KEY=8f2c1d\nDB_PASSWORD=hunter2\n" > s/plain.env

ssenc_encrypt --fresh --ssh-key s/alice.pub -i s/plain.env -o s/lib.ssh.enc
ssenc_decrypt --ssh-key s/alice.pub -i s/lib.ssh.enc
ssenc_decrypt --ssh-key "$(ssh-keygen -lf s/alice.pub | cut -d " " -f 2)" -i s/lib.ssh.enc
SSH_AUTH_SOCK="$PWD/s/agent.sock" ssenc_decrypt --ssh-key s/alice.pub -i s/lib.ssh.enc     # a specific agent for one call
EOF
bash s/demo.sh
```

## case-023-lib_ssh_key_with_own_signer

An ssh key that is not in an agent (a file, a vault, a hardware module): you supply the function that signs.

The key of this case: an Ed25519 private key in a PEM file, and its public key as an OpenSSH line.

```sh
openssl genpkey -algorithm ed25519 -out s/signer_key.pem
{
  printf "ssh-ed25519 "
  { printf "\000\000\000\013ssh-ed25519\000\000\000\040"; openssl pkey -in s/signer_key.pem -pubout -outform DER | tail -c 32; } | base64 | tr -d "\n"
  printf " demo signer key\n"
} > s/signer_key.pub
ssh-keygen -lf s/signer_key.pub
```

```sh
cat > s/demo.ts <<'EOF'
import { createPrivateKey, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { encrypt, decryptToString } from "../typescript/dist/ssenc.node.ts";
import type { SshSigner } from "../typescript/dist/ssenc.node.ts";

const privateKey = createPrivateKey(readFileSync("s/signer_key.pem"));
const publicKey = readFileSync("s/signer_key.pub", "utf8");
const sshString = (b: Uint8Array) => { const n = Buffer.alloc(4); n.writeUInt32BE(b.length); return Buffer.concat([n, b]); };

// returns what an ssh-agent would return: string(algorithm) followed by string(signature)
const signer: SshSigner = async (publicKeyBlob, data) =>
  Buffer.concat([sshString(Buffer.from("ssh-ed25519")), sshString(sign(null, data, privateKey))]);

const key = { type: "ssh", publicKey, signer } as const;      // publicKey is required with a signer
const encrypted = await encrypt("API_KEY=8f2c1d\n", key);
console.log(encrypted);
console.log(await decryptToString(encrypted, key));
EOF
SSH_AUTH_SOCK= node s/demo.ts                                 # no agent is involved
```

```sh
cat > s/app/src/main.rs <<'EOF'
use ssenc::{decrypt, encrypt, EncryptOptions, Error, ErrorKind, Key, SshSigner};
use std::{fs, process::Command, sync::Arc};

// SSH wire format of a byte string: 4-byte big-endian length, then the bytes
fn ssh_string(bytes: &[u8]) -> Vec<u8> {
    [&(bytes.len() as u32).to_be_bytes()[..], bytes].concat()
}

// 64 bytes, from wherever the key lives; here the openssl command signs with the PEM file
fn my_ed25519_sign(data: &[u8]) -> Result<Vec<u8>, Error> {
    let env = |message: String| Error { kind: ErrorKind::Env, message };
    fs::write("s/to-sign.bin", data).map_err(|e| env(e.to_string()))?;
    let args = ["pkeyutl", "-sign", "-inkey", "s/signer_key.pem", "-rawin", "-in", "s/to-sign.bin"];
    Ok(Command::new("openssl").args(args).output().map_err(|e| env(e.to_string()))?.stdout)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // returns what an ssh-agent would return: string(algorithm) followed by string(signature)
    let signer: SshSigner = Arc::new(|_public_key_blob: &[u8], data: &[u8]| {
        let signature = my_ed25519_sign(data)?;
        Ok([ssh_string(b"ssh-ed25519"), ssh_string(&signature)].concat())
    });
    let public_key = fs::read_to_string("s/signer_key.pub")?;   // required with a signer
    let key = Key::Ssh { public_key: Some(public_key), fingerprint: None, agent_socket: None, signer: Some(signer) };

    let encrypted = encrypt(b"API_KEY=8f2c1d\n", &[key.clone()], &EncryptOptions::default())?;
    println!("{encrypted}");
    println!("{}", String::from_utf8(decrypt(encrypted.as_bytes(), &key)?)?);
    Ok(())
}
EOF
SSH_AUTH_SOCK= cargo run -q --manifest-path s/app/Cargo.toml      # no agent is involved
```

```sh
# Bash has no signer function; it can only choose which agent is asked (here the one of case-011)
cat > s/demo.sh <<'EOF'
source bash/ssenc.sh
printf "API_KEY=8f2c1d\n" > s/plain.env

SSH_AUTH_SOCK="$PWD/s/agent.sock" ssenc_encrypt --fresh --ssh-key s/alice.pub -i s/plain.env -o s/lib.agent.enc
SSH_AUTH_SOCK="$PWD/s/agent.sock" ssenc_decrypt --ssh-key s/alice.pub -i s/lib.agent.enc
EOF
bash s/demo.sh
```

## case-024-lib_many_encryptions_fast

Many encryptions from one program: random key, minimum password cost, all cores, key cache.

```sh
openssl rand -base64 32 > s/bulk.key
rm -rf s/plain && mkdir -p s/plain
for i in 1 2 3 4 5 6 7 8; do printf "file $i\nsecret: $RANDOM\n" > s/plain/$i.txt; done
```

```sh
cat > s/demo.ts <<'EOF'
import { readFileSync, readdirSync } from "node:fs";
import { encrypt, setKdfCacheSize } from "../typescript/dist/ssenc.node.ts";

const names = readdirSync("s/plain").map((name) => `s/plain/${name}`);
const timed = async (label: string, work: () => Promise<unknown>) => {
  const start = performance.now();
  await work();
  console.log(label, Math.round(performance.now() - start), "ms");
};

const human = { type: "password", password: "correct horse battery staple" } as const;
const bulkKey = { type: "password", password: readFileSync("s/bulk.key", "utf8").trim() } as const;
const minimum = { kdf: "m=8,t=1,p=1" } as const;      // only for a random key, never for a human password

await timed("default cost, 2 files:", async () => { for (const name of names.slice(0, 2)) await encrypt(readFileSync(name), human); });
await timed("minimum cost, 8 files:", () => Promise.all(names.map((name) => encrypt(readFileSync(name), bulkKey, minimum))));

setKdfCacheSize(8);   // same password + same file again and again: the derived key is remembered
let current = await encrypt("draft 1\n", human);
await timed("update with the key cache:", async () => { current = await encrypt("draft 2\n", human, { previous: current }); });
setKdfCacheSize(0);   // off, keys forgotten
await timed("update without it:", async () => { current = await encrypt("draft 3\n", human, { previous: current }); });
EOF
node s/demo.ts
```

```sh
cat > s/app/src/main.rs <<'EOF'
use ssenc::{encrypt, EncryptOptions, Key};
use std::{fs, time::Instant};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let names: Vec<_> = fs::read_dir("s/plain")?.map(|entry| entry.unwrap().path()).collect();
    let human = Key::password("correct horse battery staple");
    let bulk_key = Key::password(fs::read_to_string("s/bulk.key")?.trim());
    let minimum = EncryptOptions { kdf: Some("m=8,t=1,p=1".into()), ..Default::default() };   // only for a random key

    let start = Instant::now();
    for name in &names[..2] {
        encrypt(&fs::read(name)?, &[human.clone()], &EncryptOptions::default())?;
    }
    println!("default cost, 2 files: {:?}", start.elapsed());

    let start = Instant::now();
    let (bulk_key, minimum) = (&bulk_key, &minimum);
    std::thread::scope(|scope| {
        for name in &names {
            scope.spawn(move || encrypt(&fs::read(name).unwrap(), &[bulk_key.clone()], minimum).unwrap());
        }
    });
    println!("minimum cost, {} files on threads: {:?}", names.len(), start.elapsed());
    Ok(())
}
EOF
cargo run -q --release --manifest-path s/app/Cargo.toml      # --release: this one is about speed
```

```sh
cat > s/demo.sh <<'EOF'
source bash/ssenc.sh
rm -rf s/encrypted && mkdir -p s/encrypted

for f in s/plain/*.txt; do
  ssenc_encrypt --kdf m=8,t=1,p=1 --password-file s/bulk.key -i "$f" -o "s/encrypted/$(basename "$f").enc" &
done
wait
ls s/encrypted
EOF
time bash s/demo.sh
```

## Clean up

Stop the private agent of case-011 and bring `s/` back to what is in git.

```sh
eval "$(ssh-agent -k)"                 # stops the private agent; a new terminal has your own agent again
git checkout -- s
git clean -ffdx s                      # -ff: also the throwaway repository s/repo
```
