# PLAN: `ssenc` — password / ssh-agent encryption to diff-friendly ASCII

Three interoperable implementations (TypeScript, Rust, Bash) of one file format, with one
shared test suite that proves every implementation can read what every other one wrote.

`ssenc` is a working name (see [Open decisions](#12-open-decisions)).

---

## 1. Summary of the proposal

| Topic | Proposal |
|---|---|
| Password → key | **Argon2id** (memory-hard), parameters stored in the file header |
| Cipher | **AES-256-CTR + HMAC-SHA-256 in SIV composition** (deterministic, misuse-resistant, authenticated) |
| Key layout | Envelope: a random 256-bit **data key** per file, wrapped once per **key slot** (password and/or ssh key) |
| Line mode | Each line is encrypted on its own; unchanged lines produce identical ciphertext, so `git diff` shows which lines changed |
| Blob mode | Whole input (binary or text) in 64 KiB authenticated chunks, base64, wrapped at 76 columns |
| SSH mode | Key is derived from a **deterministic signature made by `ssh-agent`** (Ed25519 or RSA). The private key never leaves the agent; you type its passphrase once per login as usual |
| Unified delivery | Each language ships a library **and** a CLI `bin/ssenc` with identical commands, flags and exit codes. Tests drive the CLIs |
| Tests | Shared known-answer vectors + full 3×3 encrypt/decrypt matrix + 3×3×3 rekey matrix |

All of the building blocks were checked on this machine before writing the plan
(see [section 11](#11-what-was-verified-already)).

---

## 2. Requirements → how each is met

| Requirement | Answer |
|---|---|
| Encrypt text to an ASCII string | Output alphabet is base64url + a `#` header; always 7-bit ASCII |
| Encrypt binary files to ASCII text files | Blob mode |
| Decrypt and re-encrypt with a new key | `rekey` in every library and CLI |
| Line-by-line, see which lines changed | Line mode with deterministic per-line encryption |
| Leading/trailing whitespace kept in clear, inner whitespace encrypted | `preserveWhitespace` parameter on `encrypt` (default `true`) |
| Password mode | Argon2id key slot |
| SSH-key mode, unlocked once per OS session | ssh-agent signature key slot |
| mac, Linux, ideally Windows | Unix socket on mac/Linux, `\\.\pipe\openssh-ssh-agent` on Windows |
| TypeScript as a single file | `typescript/dist/ssenc.ts`, zero runtime dependencies |
| Same interface in all languages | Same four operations, same option names, same CLI |
| Per-language directories with tests | `typescript/`, `rust/`, `bash/`, plus shared `tests/` |
| Cross-implementation tests | `tests/run.sh` matrix |
| `compile.sh`, `install.sh`, `envverify.sh` per language | Present in every language directory and at the root |

---

## 3. Cryptographic design

### 3.1 Why not just AES-GCM / ChaCha20-Poly1305

Two constraints rule out the usual choices:

1. **Unchanged lines must encrypt to the same bytes**, otherwise every re-encryption rewrites
   the whole file in git. That means no random nonce per line. Reusing a nonce with GCM or
   ChaCha20-Poly1305 is catastrophic. The correct tool is a **deterministic AEAD (SIV)**,
   which is designed for exactly this and leaks only "these two plaintexts are equal".
2. **Bash can only use what the `openssl` CLI exposes.** `openssl enc` refuses AEAD modes
   (GCM, SIV, ChaCha20-Poly1305). It does expose AES-256-CTR, HMAC-SHA-256 and Argon2id.

So the cipher is the generic SIV construction (Rogaway–Shrimpton) built from two
conservative primitives available everywhere:

```
tag = HMAC-SHA-256(K_mac, AD_len(8 BE) || AD || plaintext)[0..16]
iv  = tag with bit 63 and bit 31 cleared        (same trick as RFC 5297, avoids counter-carry differences)
ct  = AES-256-CTR(K_enc, iv, plaintext)
out = tag || ct

decrypt: recompute iv from tag, decrypt, recompute tag, constant-time compare, fail closed
```

Properties: 256-bit keys, 128-bit authentication tag, nonce-misuse resistant, key-committing
(HMAC), no primitive weaker than what TLS uses. The trade-off against RFC 5297 AES-SIV is
that this is a composition specified by us rather than an RFC — it is what lets Bash take
part. `SPEC.md` will define it byte-for-byte and the test vectors pin it.

### 3.2 Keys

```
data key (DEK)   32 random bytes, generated once per encrypted file
K_line_mac, K_line_enc, K_blob_mac, K_blob_enc, K_seal
                 = HKDF-SHA-256(DEK, info = "ssenc1/<purpose>")
key slot         = SIV-encrypt(KEK, DEK), where KEK comes from a password or an ssh signature
```

Why an envelope instead of using the password-derived key directly:

- A file can have **several slots**, e.g. your ssh key for daily use **and** a backup
  password. Losing the ssh key then does not lose the data.
- Argon2id runs once per file, not once per line.
- `rekey` can either rewrap the DEK (only the header line changes) or rotate it (default).

### 3.3 Password slot

`KEK = Argon2id(password bytes, 16-byte random salt, m, t, p)`.

- Default `m=64 MiB, t=3, p=4` (RFC 9106 second recommended profile).
  `--kdf strong` → `m=1 GiB, t=4, p=4`. Parameters are written to the header, so they can be
  raised later without a format change.
- Password is used as raw UTF-8 bytes, **no Unicode normalisation** (Bash cannot do it
  reliably; documented).
- CLI reads the password from `SSENC_PASSWORD`, `--password-file`, or a TTY prompt.
  Never from an argument.

### 3.4 SSH-agent slot

`ssh-agent` can only sign, it cannot decrypt. But Ed25519 and RSA (PKCS#1 v1.5) signatures
are deterministic, so a signature over a fixed challenge is a stable secret only the key
holder can produce:

```
challenge = "ssenc1 ssh slot" || 32-byte random slot salt
sig       = agent.sign(SSHSIG blob: namespace "ssenc-v1@stopsopa", hash sha512, message = challenge)
KEK       = HKDF-SHA-256(sig, salt = slot salt, info = "ssenc1/ssh-kek")
```

- Uses the standard **SSHSIG** format, so Bash gets the identical signature from
  `ssh-keygen -Y sign -f key.pub -n ssenc-v1@stopsopa`, while TypeScript and Rust talk the
  agent protocol directly over `SSH_AUTH_SOCK` / the Windows named pipe.
- The dedicated namespace means no ssh login, git commit signature or other tool ever
  produces a signature over the same bytes.
- Supported: `ssh-ed25519`, `ssh-rsa` (signed as `rsa-sha2-512`).
  **Rejected with a clear error:** ECDSA and FIDO `sk-*` keys — their signatures are
  randomised, so the key could never be re-derived.
- Both encrypt and decrypt need the agent (it is symmetric in practice).
- Slot records the key's `SHA256:` fingerprint so the right agent key is picked automatically.

Limits to be aware of:

- Anyone who can make your agent sign can derive the key. **Do not use with agent
  forwarding to untrusted hosts.**
- If the ssh key is lost, that slot is dead. Add a password slot as a backup.

Alternatives considered and rejected: `age` with ssh keys (needs the private key file, no
agent support), RSA public-key encryption to `id_rsa.pub` (same problem on decrypt),
GPG (heavy dependency, poor Windows story).

---

## 4. File format (`ssenc1`)

### 4.1 Header

```
#ssenc1 lines ws=1 pad=16
#slot pw argon2id m=65536,t=3,p=4 <salt b64url> <wrapped DEK b64url>
#slot ssh ssh-ed25519 SHA256:AbC... <salt b64url> <wrapped DEK b64url>
```

Header lines start with `#` in column 0. `#` is not in the base64url alphabet, so a header
line can never be mistaken for a body line.

### 4.2 Line mode

For each line:

```
<leading ws> <core> <trailing ws> <LF or CRLF>
```

- Whitespace = space (0x20) and tab (0x09) only. Other Unicode spaces are part of the core.
- The line terminator (LF or CRLF, or none on the last line) is always preserved as is.
- `ws=1` (preserve): leading/trailing whitespace stays in clear, core is encrypted.
  A line with an empty core is emitted unchanged.
- `ws=0`: the whole line except the terminator is encrypted.
- Core is padded (0x80 then zeros) to a multiple of `pad` bytes so token length only reveals
  the length bucket. `pad=0` disables.
- Token = `base64url(tag || ct)` without `=` padding.
- Works on bytes; lines do not have to be valid UTF-8.
- Decrypt needs no flag: strip surrounding whitespace, decrypt token, put whitespace back.

Example:

```
plain                       encrypted
----------------------      ------------------------------------------
server:                     q0J3nXvZk1cP8sYtR2uVwA7mB4dLhE9fGiNoKpQrSt
    host: db.internal           Zx9cV2bN5mK8jH1gF4dS7aP0oI3uY6tR9eW2qLzXcV
    port: 5432                  Mn4bV7cX0zL3kJ6hG9fD2sA5pO8iU1yT4rE7wQ0aBc
```

**What line mode deliberately leaks** (this is the price of readable diffs): number of
lines, indentation, blank lines, length bucket of each line, and whether two lines in the
same file are identical. Different files use different data keys, so nothing is comparable
across files. For secrets where that is too much, use blob mode.

**What line mode does not protect:** each line is authenticated individually, so someone
with write access to the repo could delete, reorder or duplicate whole lines without
detection. Optional `--seal` adds a `#seal` MAC over the whole file; it is off by default
because it changes on every edit and therefore conflicts on every git merge.

### 4.3 Blob mode

```
#ssenc1 blob chunk=65536
#slot ...
<base64, 76 columns>
```

Input is cut into 64 KiB chunks; each is SIV-encrypted with
`AD = chunk index || final flag`, which detects truncation, reordering and appended data.
Works for binary and for text you do not want line-visible.

### 4.4 Stable diffs across re-encryption

Determinism depends on reusing the same data key. `encrypt` therefore accepts the
**previous encrypted version** (`previous` option / `--previous <file>`, and the CLI uses
the output file itself when it already exists): the header and slots are reused, and only
changed lines differ. Without `previous`, a fresh data key is generated and every line
changes.

---

## 5. Interface (identical in all three languages)

### 5.1 Library

| Operation | Signature (TypeScript notation) |
|---|---|
| `encrypt` | `(input: bytes, key: Key \| Key[], opts?) → ascii` |
| `decrypt` | `(input: ascii, key: Key) → bytes` |
| `rekey` | `(input: ascii, oldKey: Key, newKey: Key \| Key[], opts?) → ascii` |
| `inspect` | `(input: ascii) → { mode, ws, pad, slots[] }` (no key needed) |

```
Key  = { type: "password", password }
     | { type: "ssh", publicKey | fingerprint, agentSocket? }

encrypt opts = { mode: "lines" | "blob"      (default "lines")
                 preserveWhitespace: boolean (default true, lines mode only)
                 pad: number                 (default 16)
                 kdf: "default" | "strong" | { m, t, p }
                 previous?: ascii            (reuse data key → stable diffs)
                 seal: boolean               (default false) }

rekey opts   = { rotateDataKey: boolean      (default true: full re-encrypt;
                                              false: only rewrap, body unchanged) }
```

Naming per language: TS `encrypt` (async, WebCrypto), Rust `ssenc::encrypt`
(returns `Result`), Bash `ssenc_encrypt` (sourceable `ssenc.sh`, stdin → stdout, same
option names as long flags). Errors map to the same four kinds everywhere.

### 5.2 CLI (`<lang>/bin/ssenc`)

```
ssenc encrypt [--mode lines|blob] [--no-preserve-ws] [--pad N] [--kdf P] [--seal]
              [--previous FILE] KEYOPTS [-i IN] [-o OUT]
ssenc decrypt KEYOPTS [-i IN] [-o OUT]
ssenc rekey   KEYOPTS --new-password-file F | --new-ssh-key PUB [--rewrap-only] [-i IN] [-o OUT]
ssenc inspect [-i IN]

KEYOPTS:  --password-file F | env SSENC_PASSWORD | TTY prompt
          --ssh-key PUBFILE_OR_FINGERPRINT   (repeatable on encrypt → several slots)
```

| Exit code | Meaning |
|---|---|
| 0 | success |
| 1 | usage error |
| 2 | authentication failed (wrong key or tampered data) |
| 3 | malformed input |
| 4 | environment error (no agent, key not in agent, unsupported key type) |

The CLI is the unification layer for tests. No servers or wrappers are needed: a process
with stdin/stdout is the one thing all three languages do natively.

---

## 6. Repository layout

```
PLAN.md
SPEC.md                    normative format spec (written first, in M0)
envverify.sh install.sh compile.sh test.sh     run the same script in every language dir + tests/

typescript/
  envverify.sh install.sh compile.sh test.sh
  src/                     core.ts siv.ts argon2id.ts format.ts lines.ts blob.ts sshagent.ts index.ts cli.ts
  dist/ssenc.ts            THE single-file library (generated, committed)
  dist/ssenc.js            same, transpiled
  bin/ssenc                node dist/cli.js
  test/

rust/
  envverify.sh install.sh compile.sh test.sh
  Cargo.toml  src/lib.rs  src/main.rs  tests/
  bin/ssenc                → target/release/ssenc

bash/
  envverify.sh install.sh compile.sh test.sh
  ssenc.sh                 sourceable library
  bin/ssenc                CLI
  test/

tests/
  run.sh                   cross-implementation runner (bash, TAP output)
  impls.sh                 registry: name → path of bin/ssenc
  fixtures/                plaintext samples (see 8.1)
  vectors/                 known-answer vectors
  keys/                    generated at test time, git-ignored
```

---

## 7. Per-language notes

### 7.1 TypeScript

- Primitives: **WebCrypto** (`AES-CTR`, `HMAC`, `HKDF`) — works unchanged in Node ≥ 20,
  Deno, Bun and browsers. API is async.
- Argon2id is not in WebCrypto: vendor the audited `@noble/hashes` Argon2id + BLAKE2b
  sources (MIT, attribution kept) into `src/`.
- ssh-agent: `node:net` loaded by dynamic import only when an ssh key is used, so the same
  file still loads in a browser (password mode only there).
- `compile.sh`: typecheck → concatenate `src/` modules in dependency order into
  `dist/ssenc.ts` (small script, sources written with unique top-level names) →
  typecheck the result → transpile to `dist/ssenc.js` and `dist/cli.js` with esbuild.
  Tests run against `dist/`, not `src/`.
- Dev dependencies only: `typescript`, `esbuild`. Runtime dependencies: none.

### 7.2 Rust

- RustCrypto crates: `aes`, `ctr`, `hmac`, `sha2`, `hkdf`, `argon2`, `subtle`, `zeroize`,
  `base64ct`, `getrandom`; `clap` for the CLI. ssh-agent client hand-written (two message
  types) over `UnixStream` / Windows named pipe.
- Library crate + `ssenc` binary. `compile.sh` = `cargo build --release --locked`.
- Fastest implementation; recommended one for real git usage.

### 7.3 Bash

- Bash ≥ 4 + **OpenSSL ≥ 3.2** (`openssl kdf ARGON2ID`, `openssl enc -aes-256-ctr`,
  `openssl dgst -mac HMAC`) + `ssh-keygen` ≥ 8.1 + `xxd`, `base64`.
  macOS's built-in `/usr/bin/openssl` is LibreSSL and is **not** sufficient; Homebrew
  `openssl@3` is. `envverify.sh` checks for the capability, not just the version.
- Binary data never sits in a shell variable (NUL bytes); everything flows as hex.
- `compile.sh` runs `bash -n` and `shellcheck`; nothing to build.
- Two honest limitations, to be documented in the README:
  1. **Speed.** Two `openssl` processes per line, measured ≈ 17 ms per line here:
     1,000 lines ≈ 17 s. Fine for config/secret files, not for bulk data.
  2. **Key exposure on the local machine.** `openssl` only accepts raw keys as
     command-line arguments, which other processes of the same host can see in `ps` while
     the command runs. Acceptable on a personal machine; on shared hosts use the Rust CLI.

---

## 8. Testing

### 8.1 Shared fixtures

Empty file · single line without trailing newline · LF and CRLF · tabs and mixed
indentation · whitespace-only lines · duplicate lines · UTF-8 multibyte and emoji ·
invalid UTF-8 bytes · very long line (64 KiB) · line that looks like a header (`#ssenc1 …`)
· 1 MiB random binary · binary containing NUL · sizes of exactly 0, 1, 65535, 65536, 65537 bytes.

### 8.2 Layers

1. **Known-answer vectors** (`tests/vectors/`): primitive level (SIV, HKDF, Argon2id) and
   file level. Because encryption is fully deterministic once a header is given, the vector
   is simply `encrypt(fixture, key, previous = vector header) == expected bytes`.
   No test-only randomness hook is needed in production code.
2. **Cross matrix**: for every encryptor E and decryptor D in {ts, rust, bash} (9 pairs) ×
   every fixture × {lines ws=1, lines ws=0, blob} × {password, ssh-ed25519, ssh-rsa,
   password+ssh}: `D.decrypt(E.encrypt(x)) == x`.
3. **Rekey matrix**: encrypt with A, rekey with B, decrypt with C (27 combinations), both
   `rotateDataKey` settings; assert the old key no longer works.
4. **Diff stability**: change one line, re-encrypt with `--previous` using a *different*
   implementation, assert exactly one body line differs.
5. **Negative tests** with exact exit codes: wrong password (2), flipped bit in a token (2),
   truncated blob (2), swapped blob chunks (2), garbage header (3), ECDSA key (4),
   key missing from agent (4).
6. **Per-language unit tests** via `<lang>/test.sh` (`node --test`, `cargo test`, plain bash).

SSH tests start a private throwaway `ssh-agent` on a short socket path under `mktemp -d`,
load generated passphrase-protected test keys through `SSH_ASKPASS`, and kill the agent in a
`trap`. They never touch the developer's own agent.

### 8.3 The three scripts

`envverify.sh` checks everything and reports **all** problems at once, each as: what is
missing, what was found, how to fix. Exit code = number of problems. Example:

```
[FAIL] openssl: Argon2id not available
       found:  /usr/bin/openssl (LibreSSL 3.3.6) — 'kdf' command missing
       need:   OpenSSL >= 3.2
       fix:    brew install openssl@3 && export PATH="$(brew --prefix openssl@3)/bin:$PATH"
[ OK ] bash 5.3.9 (>= 4.0)
[ OK ] ssh-keygen: OpenSSH 10.3 (>= 8.1, -Y sign supported)
```

| Dir | `envverify.sh` checks | `install.sh` | `compile.sh` |
|---|---|---|---|
| typescript | node ≥ 20, npm, `node_modules` present | `npm ci` | typecheck, bundle to single file, transpile |
| rust | cargo, rustc ≥ pinned MSRV, registry reachable or vendored | `cargo fetch --locked` | `cargo build --release --locked` |
| bash | bash ≥ 4, openssl with Argon2id + CTR + HMAC (functional probe), ssh-keygen `-Y`, xxd, base64, shellcheck (warn only) | prints package-manager command for anything missing; installs nothing silently | `bash -n`, shellcheck |
| tests | all three `bin/ssenc` exist and answer `--version`, ssh-agent, ssh-add | — | — |

---

## 9. Milestones

| # | Deliverable | Done when |
|---|---|---|
| M0 | `SPEC.md` + hand-computed primitive vectors | Spec reviewed; vectors reproduced by a throwaway script |
| M1 | Rust library + CLI, password mode, lines + blob | Rust passes vectors and its own round trips; becomes the reference |
| M2 | `tests/` harness, fixtures, `envverify/install/compile/test.sh` skeleton | Matrix runs with one implementation registered |
| M3 | TypeScript single file + CLI | 2×2 matrix green |
| M4 | Bash library + CLI | 3×3 matrix green |
| M5 | SSH-agent slots in all three | ssh matrix green on mac + Linux |
| M6 | `rekey`, multi-slot, `--seal`, negative tests | Full suite green |
| M7 | CI: GitHub Actions on macOS, Ubuntu, Windows (Git Bash for the bash impl) | Green on all three |
| M8 | README, threat-model section, git usage guide | — |

Rust goes first because its crates are the most trustworthy check of the spec; Bash goes
last because it is the most constrained and benefits from a stable spec.

---

## 10. Threat model in one paragraph

Protects the confidentiality and per-line/per-chunk integrity of file contents against
anyone who obtains the repository, including full history, without the password or ssh key.
Password strength still matters: Argon2id slows guessing, it does not rescue a weak
password. It does not hide file names, file sizes, line structure (line mode), or the fact
that a line changed in a given commit — the last one is the requested feature. It does not
protect against malware on the machine where files are decrypted, nor against a compromised
or forwarded ssh-agent.

---

## 11. What was verified already

Checked on this machine (macOS, OpenSSL 4.1.0 from Homebrew, OpenSSH 10.3, Node 24.12):

| Assumption | Result |
|---|---|
| `openssl kdf … ARGON2ID` works from the CLI | Yes, 64 MiB/t=3 in 0.17 s |
| `openssl enc -aes-256-ctr -K -iv` and `openssl dgst -mac HMAC` work with raw hex keys | Yes |
| System `/usr/bin/openssl` is enough | **No** — LibreSSL 3.3.6 has no `kdf` command |
| Bash cost per line (HMAC + CTR) | ≈ 17 ms |
| `ssh-keygen -Y sign -f key.pub` signs through the agent | Yes |
| Ed25519 and RSA agent signatures are deterministic and equal to private-key-file signatures | Yes, both |
| ECDSA signatures are deterministic | **No** — must be rejected |
| Raw agent-protocol signature (Node, `SSH_AUTH_SOCK`) is byte-identical to the one inside `ssh-keygen`'s SSHSIG output | Yes, for Ed25519 and RSA |
| Agent socket path length | Long paths fail ("too long for Unix domain socket") — tests must use a short `mktemp` path |

Not yet verified: Windows named-pipe agent, Git Bash behaviour, Argon2id speed of the
pure-TypeScript implementation (expected a few seconds at 64 MiB).

---

## 12. Open decisions

1. **Name** of the tool and format magic: `ssenc` / `#ssenc1` is a placeholder.
2. **Default Argon2id cost**: 64 MiB/t=3 (proposed) vs. 256 MiB+. Higher is stronger but the
   pure-TypeScript Argon2id gets slow; to be settled with a benchmark in M3.
3. **Padding default**: `pad=16` (proposed, hides exact line lengths, tokens ~11 chars
   longer on average) vs. `pad=0`.
4. **`rekey` default**: rotate the data key (proposed; every line changes once) vs.
   rewrap only (one-line diff, but an old password plus an old clone still reads new commits).
5. **Git integration** (clean/smudge filter or a `git ssenc` helper) is out of scope for
   this plan; the `--previous` mechanism is designed so it can be added later.
6. **Bash as pure Bash + openssl** (proposed, with the two limitations in 7.3) vs. allowing
   it to call a small helper binary, which would remove both limitations but make it less
   of an independent implementation.
