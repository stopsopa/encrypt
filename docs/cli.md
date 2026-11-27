# ssenc — command line

Every implementation ships the same command with the same options, output and exit codes,
and they read each other's files:

| Command | Implementation | Needs |
|---|---|---|
| `rust/bin/ssenc` | Rust (fastest; recommended for everyday use) | `rust/compile.sh` once |
| `typescript/bin/ssenc` | TypeScript, run directly by Node | Node.js ≥ 22.18, nothing to build |
| `bash/bin/ssenc` | Bash + `openssl` | bash ≥ 4, OpenSSL ≥ 3.2 (not the LibreSSL that ships with macOS) |

To have it as `ssenc` everywhere, link the one you want into your `PATH`, e.g.
`ln -s "$PWD/rust/bin/ssenc" ~/bin/ssenc`.

The Rust command is also released as a single binary, usable without a clone of the repository
and able to update itself (`ssenc --update`): see [Install](../README.md#install).

Other documents: [TypeScript library](typescript.md) · [Rust library](rust.md) · [format specification](../SPEC.md)

## Commands

```
ssenc encrypt [--mode lines|blob|auto] [--no-preserve-ws] [--pad N] [--chunk N] [--kdf PROFILE]
              [--seal] [--previous FILE | --fresh] KEYS [-i IN] [-o OUT]
ssenc decrypt KEY [-i IN] [-o OUT]
ssenc rekey   KEY NEWKEYS [--kdf PROFILE] [--rewrap-only] [-i IN] [-o OUT]
ssenc inspect [-i IN]
ssenc --version
ssenc --update [TAG | --check]          Rust binary only, see "Updating" below
```

`-i` and `-o` default to standard input and standard output. The input is read completely
before the output is written, so both may name the same file.

## Giving the key

| How | Notes |
|---|---|
| `--password-file FILE` | the file's content, without one trailing newline |
| `SSENC_PASSWORD` environment variable | used when there is no `--password-file` |
| prompt | when neither is given, no `--ssh-key` is given, the terminal is interactive and `-i` names a file |
| `--ssh-key FILE.pub` | an ssh public key whose private key is loaded in `ssh-agent` |
| `--ssh-key SHA256:…` | the same, naming the key by fingerprint (see `ssh-add -l`) |

A password is never accepted as a command-line argument: arguments are visible to other
processes.

`encrypt` accepts a password and any number of `--ssh-key` at once; the file can then be
opened with any one of them. `decrypt` and `rekey` use one key: `--ssh-key` if given,
otherwise the password.

New keys for `rekey`: `--new-password-file FILE`, `SSENC_NEW_PASSWORD`, `--new-ssh-key …`.

## encrypt

```sh
export SSENC_PASSWORD='correct horse battery staple'

ssenc encrypt -i config.yml -o config.yml.enc            # line by line (default)
ssenc encrypt --mode blob -i photo.jpg -o photo.jpg.enc  # any bytes, as a whole
ssenc encrypt --mode auto -i "$file" -o "$file.enc"      # lines for text, blob for anything else
cat notes.txt | ssenc encrypt > notes.txt.enc            # stdin -> stdout
```

| Option | Default | Meaning |
|---|---|---|
| `--mode lines\|blob\|auto` | `lines` | `lines`: every input line becomes one encrypted line. `blob`: the input is encrypted as a whole. `auto`: `lines` for text, `blob` for anything else (see below). |
| `--no-preserve-ws` | off | Lines mode: also encrypt leading and trailing spaces/tabs. By default they stay as they are, so indentation remains visible. |
| `--pad N` | `16` | Lines mode: pad each line to a multiple of N bytes; `0` disables. |
| `--chunk N` | `65536` | Blob mode: chunk size in bytes. |
| `--kdf PROFILE` | `default` | Argon2id cost for the password: `default` (64 MiB, 3 passes), `strong` (1 GiB, 4 passes) or `m=<KiB>,t=<passes>,p=<lanes>`. |
| `--seal` | off | Lines mode: add a checksum over the whole file so removed, added or reordered lines are detected. |
| `--previous FILE` | — | Reuse the data key of an earlier encrypted version: unchanged lines stay identical. |
| `--fresh` | off | Do not reuse an existing output file (see below). |

### `--mode auto`: text or binary?

For encrypting many files of unknown kind with one command. The input counts as text, and
is encrypted line by line, when it contains no NUL byte and is valid UTF-8; an empty input
is text too. Everything else (images, archives, UTF-16 or Latin-1 text) is encrypted as a
blob. The whole input is examined, not only its beginning.

```sh
for f in secrets/*; do ssenc encrypt --mode auto -i "$f" -o "encrypted/$(basename "$f").enc"; done
```

- A wrong guess never loses data: both modes take any bytes and `decrypt` reads the mode
  from the file. It only costs diff-friendliness (text taken for binary) or a little size.
- **An existing file keeps its mode.** When the output file exists (or `--previous` is
  given), `auto` means "as in that file" and nothing is detected, so one stray byte pasted
  into a config file does not turn its one-line diffs into a full rewrite. `--fresh`
  detects again.
- With `--seal`, an input that turns out to be binary is refused (exit code 1): a seal
  exists only in lines mode.

### Updating a file: only changed lines change

When `-o` names an existing ssenc file, it is used as `--previous` automatically:

```sh
ssenc encrypt -i config.yml -o config.yml.enc    # first time
# … edit config.yml …
ssenc encrypt -i config.yml -o config.yml.enc    # only the edited lines differ: git diff shows which
```

The key must open the existing file. If it does not (exit code 2), either use the right key
or pass `--fresh` to start over with a new data key.

## decrypt

```sh
ssenc decrypt -i config.yml.enc -o config.yml
ssenc decrypt --ssh-key ~/.ssh/id_ed25519.pub -i config.yml.enc

# encrypted text straight from a heredoc
ssenc decrypt <<'SSENC_EOF'
#ssenc1 lines ws=1 pad=16
#slot pw argon2id m=65536,t=3,p=4 os3aSYtRUW4mPjGMTvjwjw 2y0CzoI8qlxAPU2tyyEIJcgTWLb-kIeHzCem8AwHWVJIQrwLY3pyAk0rG3WaJI-8
PqXYBv6DPJHnspY2ZLnfpvTlwrVyJyqG3W-7CM1mISE
SSENC_EOF
```

Nothing is written when the key is wrong or the file was modified.

## rekey

```sh
export SSENC_PASSWORD='old password'
SSENC_NEW_PASSWORD='new password' ssenc rekey -i config.yml.enc -o config.yml.enc

# from a password to an ssh key plus a backup password
SSENC_NEW_PASSWORD='backup' ssenc rekey --new-ssh-key ~/.ssh/id_ed25519.pub -i config.yml.enc -o config.yml.enc
```

All previous keys stop working. By default everything is re-encrypted under a new data key,
so every line changes once. `--rewrap-only` replaces only the key lines at the top and
leaves the rest byte-identical; that is cheaper, but someone who has the old key and an old
copy of the file can still read later versions.

## inspect

No key needed. Prints one line of JSON:

```sh
$ ssenc inspect -i config.yml.enc
{"format":"ssenc1","mode":"lines","ws":true,"pad":16,"seal":false,"slots":[{"type":"pw","kdf":"argon2id","m":65536,"t":3,"p":4}]}
```

## SSH keys

```sh
ssh-add ~/.ssh/id_ed25519                        # once per login; asks for the key's passphrase
ssenc encrypt --ssh-key ~/.ssh/id_ed25519.pub -i secrets.env -o secrets.env.enc
ssenc decrypt --ssh-key ~/.ssh/id_ed25519.pub -i secrets.env.enc
```

- Both encrypting and decrypting need the key to be loaded in the agent.
- Supported key types: `ssh-ed25519` and `ssh-rsa`. ECDSA and hardware (`sk-…`) keys are
  refused: their signatures differ every time, so the key could never be derived again.
- Add a password as a second key when encrypting (`SSENC_PASSWORD=… ssenc encrypt --ssh-key …`):
  if the ssh key is lost, the password still opens the file.
- Do not use this with agent forwarding to machines you do not trust: whoever can ask your
  agent to sign can derive the key.

## Exit codes

| Code | Name | Meaning |
|---|---|---|
| 0 | | success |
| 1 | USAGE | bad arguments, no command, empty password, no key given, a file that cannot be read or written |
| 2 | AUTH | wrong key, or the file was modified |
| 3 | MALFORMED | the input is not a valid ssenc1 file |
| 4 | ENV | ssh-agent not reachable, key not loaded in the agent, unsupported key type |

Errors go to standard error as `ssenc: <NAME>: <message>`, and nothing is written to the
output. Exit code 0 always means that the operation succeeded and the whole output was
written.

In a pipeline the shell reports the exit code of the **last** command, not of `ssenc`:

```sh
ssenc inspect -i missing.enc | jq; echo $?      # 0: that is jq's exit code, ssenc exited with 1

set -o pipefail                                 # bash and zsh: a pipeline fails when any part fails
ssenc inspect -i missing.enc | jq; echo $?      # 1
```

Without `pipefail`, bash has `${PIPESTATUS[0]}` and zsh has `$pipestatus[1]` for the exit
code of the first command of the last pipeline.

## Updating (Rust binary only)

```
ssenc --update            update to the latest release
ssenc --update <tag>      install the given release (also an older one), e.g. v0.1.0
ssenc --update --check    only say whether there is something newer, change nothing
```

The binary replaces itself with a [release](https://github.com/stopsopa/encrypt/releases). It
needs `curl` or `wget`, and `sha256sum` or `shasum`. Steps:

1. `SHA256SUMS.txt` and the binary of this platform are downloaded next to the installed file,
   under a temporary name. The platform is not detected: the running binary knows what it was
   built for (`ssenc-darwin-arm64`, `ssenc-linux-x64`, `ssenc-linux-arm64`).
2. The sha256 of the download has to match `SHA256SUMS.txt`.
3. The downloaded binary is executed and has to print `ssenc rust <tag>`.
4. Only now the installed file is replaced (one atomic rename; started through a symlink, the
   real file is replaced).
5. The installed binary is executed once more. If that fails, the previous file is put back.

After any failure the installed file is exactly what it was, and no temporary file is left.

| Variable | Default | |
|---|---|---|
| `SSENC_RELEASES` | `https://github.com/stopsopa/encrypt/releases` | URL or local directory (`~/` means home) releases are taken from. `<SSENC_RELEASES>/latest`: for a URL it has to redirect to `.../tag/<tag>`, in a directory it is a file containing the tag. `<SSENC_RELEASES>/download/<tag>/`: the binaries and `SHA256SUMS.txt`. For a mirror and for tests. |
| `SSENC_CONFIRM` | `true` | `false`: no question before replacing. Without a terminal and without it, `--update` fails instead of waiting. |

Exit codes: 0 updated, already up to date, `--check`, or the answer was "no"; 1 wrong arguments;
4 everything else (no network, no such release, checksum mismatch, a binary which does not run,
directory not writable).

`ssenc --version` of a released binary prints the tag of its release (`ssenc rust v0.1.0`). A
binary built locally prints `ssenc rust dev` and refuses to update: it is not a release, there
is nothing to compare it with.

The checksum comes from the same release as the binary, so it protects against a broken or
truncated download, not against someone who controls the release.

## Differences between the three commands

Behaviour is the same; these are the practical differences:

- **Speed.** Rust and Node are fast on files of any size. Bash starts `openssl` for every
  line and every chunk: fine for configuration files, slow for large ones.
- **Privacy on shared machines.** The Bash version has to pass keys to `openssl` as
  command-line arguments, which other processes on the same machine can see while it runs.
- **Password cost.** Encrypting a 100-line file with a password at the default setting
  takes about 0.15 s with Rust, 0.6 s with Bash and 2 s with Node (measured on an Apple
  M-series laptop); most of the Node time is the password-to-key derivation.
