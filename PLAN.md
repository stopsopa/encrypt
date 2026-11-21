# PLAN: `ssenc` — password / ssh-agent encryption to diff-friendly ASCII

Three interoperable implementations (TypeScript, Rust, Bash) of one file format, with one
shared test suite that proves every implementation can read what every other one wrote.

`ssenc` is a working name (see [Open decisions](#12-open-decisions)).

> **Status: implemented.** The normative format is in [SPEC.md](SPEC.md); usage is in
> [README.md](README.md). Where the implementation differs from this plan it is listed in
> [section 13](#13-what-changed-during-implementation).

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
| Tests | Encrypt everywhere (Rust, Bash, Node on `.ts`, Node on `.js`, browser via Playwright), save to files, then decrypt everything with everything; results published as a report on GitHub Pages |

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
| TypeScript as a single file, ESM, for Node.js and for the browser, each also transpiled | `typescript/dist/ssenc.node.ts` + `ssenc.browser.ts`, with `ssenc.node.js` + `ssenc.browser.js` next to them; zero runtime dependencies |
| Same interface in all languages | Same four operations, same option names, same CLI |
| Per-language directories with tests | `typescript/`, `rust/`, `bash/`, plus shared `tests/` |
| Cross-implementation tests, incl. browser, with a published summary | 5×5 producer × consumer matrix, report on GitHub Pages (section 8) |
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
     | { type: "ssh", publicKey | fingerprint, agentSocket?, signer? }

signer = (publicKeyBlob, dataToSign) → signature     optional; default = local ssh-agent.
         Lets the caller supply the signature from elsewhere (the browser build has no
         default signer, so there it is required for ssh keys).

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

The CLI is the unification layer for tests on the server side. No servers or wrappers are
needed: a process with stdin/stdout is the one thing all three languages do natively.
The browser build has no CLI; Playwright drives it through the library API (8.3).

---

## 6. Repository layout

```
PLAN.md
SPEC.md                    normative format spec (written first, in M0)
envverify.sh install.sh compile.sh test.sh     run the same script in every language dir + tests/

typescript/
  envverify.sh install.sh compile.sh test.sh
  src/                     core.ts siv.ts argon2id.ts format.ts lines.ts blob.ts
                           sshagent.node.ts sshagent.browser.ts index.ts cli.ts
  dist/                    generated, committed; all four are self-contained ESM, no imports
    ssenc.node.ts          single-file library for Node.js (password + ssh-agent)
    ssenc.node.js          same, transpiled
    ssenc.browser.ts       single-file library for the browser (password; ssh via supplied signer)
    ssenc.browser.js       same, transpiled
    cli.ts / cli.js        CLI on top of ssenc.node.ts / ssenc.node.js
  bin/ssenc                node dist/cli.ts (native type stripping); SSENC_TS_BUILD=js → node dist/cli.js
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
  envverify.sh install.sh
  run.sh                   entry point: test ssh-agent, run.ts, report
  run.ts                   the runner: plans every check, runs the stages of 8.3
  lib/participants.ts      the five participants (4 CLIs + browser via Playwright)
  lib/cases.ts             the case list: fixture × mode × key, generated from one table
  lib/fixtures.ts          deterministic plaintext samples (see 8.1)
  lib/agent.sh             throwaway ssh-agent with the test keys
  stages/cross.ts          stages 1-3: encrypt to files, decrypt all with all
  stages/extra.ts          stage 4: vectors, rekey, diff stability, negative tests
  report/build.ts          out/ → out/report/index.html   (template.html)
  browser/harness.html     page that loads dist/ssenc.browser.js
  keys/                    fixed test-only ssh keys
  vectors/                 known-answer vectors
  out/                     everything generated; git-ignored

xx.ts                      all scripts as commands of the xx menu
.tool-versions             Node.js version (asdf), also used by CI
.github/workflows/test.yml   build, run all stages, publish report to GitHub Pages
```

---

## 7. Per-language notes

### 7.1 TypeScript

- Primitives: **WebCrypto** (`AES-CTR`, `HMAC`, `HKDF`) in both builds — the crypto core is
  one shared source, so Node and browser cannot drift apart. API is async.
- Argon2id is not in WebCrypto, so the file contains its own Argon2id + BLAKE2b
  (`src/02-blake2b.ts`, `src/03-argon2id.ts`), checked against OpenSSL's output and the
  shared vectors. See section 13 for why it is not a vendored library.
- **Four deliverables, all single-file ESM with no imports of other project files:**

  | File | Target | Contents |
  |---|---|---|
  | `dist/ssenc.node.ts` | Node.js ≥ 20 (also Deno, Bun) | everything, incl. ssh-agent client (`node:net`) |
  | `dist/ssenc.node.js` | same | transpiled from the file above |
  | `dist/ssenc.browser.ts` | browsers, web workers | password mode; ssh mode only with a caller-supplied `signer`; no `node:*` reference anywhere in the file |
  | `dist/ssenc.browser.js` | same | transpiled from the file above |

  The only difference between the two builds is which `sshagent.*.ts` module is included.
  A browser cannot open a socket to ssh-agent, so the browser build has no default signer:
  an ssh key without a `signer` throws the "environment error" kind (same as exit code 4).
  With a `signer` (5.1) the whole ssh code path — challenge, SSHSIG blob, HKDF, slot
  unwrap — runs in the browser and only the signature itself comes from outside.
  All files are interchangeable between the two builds.
- **Node runs the `.ts` file directly** (native type stripping, Node ≥ 22.18), so the
  sources use erasable syntax only (`erasableSyntaxOnly` in `tsconfig.json`: no `enum`,
  no `namespace`, no parameter properties) and import with explicit `.ts` extensions.
- `compile.sh`: typecheck `src/` → for each target, concatenate the modules in dependency
  order into `dist/ssenc.<target>.ts` (small script, sources written with unique top-level
  names) → typecheck each generated file on its own (`lib: dom` without Node types for the
  browser one, which proves it has no Node dependency) → transpile each to the `.js` next
  to it, plus `dist/cli.js`, with the TypeScript compiler's `transpileModule`.
- Tests run against `dist/`, not `src/`. All four files are exercised: see 8.2.
- Dev dependencies only: `typescript` (and `playwright` in `tests/`). Runtime: none.

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

### 8.2 Participants

Five participants take part in every cross test. Each is both a producer (encrypts) and a
consumer (decrypts):

| Id | What runs | Where | How it is driven |
|---|---|---|---|
| `rust` | `rust/target/release/ssenc` | server | CLI |
| `bash` | `bash/bin/ssenc` | server | CLI |
| `node-ts` | `dist/ssenc.node.ts`, run by Node with native type stripping | server | CLI (`node dist/cli.ts`) |
| `node-js` | `dist/ssenc.node.js` (transpiled) | server | CLI (`node dist/cli.js`) |
| `browser-js` | `dist/ssenc.browser.js` (transpiled) | headless Chromium | Playwright |

`dist/ssenc.browser.ts` cannot run in a browser as is; it is covered by the typecheck in
`compile.sh` and by being the direct source of `ssenc.browser.js`.

### 8.3 Stages

"Server" below means the machine running the tests (your laptop or the CI runner), as
opposed to the browser.

```
stage 1  server encrypt     rust, bash, node-ts, node-js encrypt every case
                            → tests/out/artifacts/<producer>/<case>.enc
stage 2  browser encrypt    Playwright opens harness.html, browser-js encrypts every case
                            → tests/out/artifacts/browser-js/<case>.enc
stage 3  decrypt all×all    every participant (browser again through Playwright) decrypts
                            every artifact of every producer; output compared by SHA-256
                            with the original fixture
                            → tests/out/results.jsonl   (one record per decrypt)
stage 4  extra suites       vectors, rekey matrix, diff stability, negative tests
                            → appended to results.jsonl
stage 5  report             results.jsonl → tests/out/report/index.html (+ results.json)
```

Encrypting first and decrypting later, from files on disk, means the artifacts are real
files that can be inspected, downloaded from CI, and decrypted by hand when a cell is red.

**How the browser reads and writes files.** The Playwright test (Node side) reads the
fixture or artifact from disk and passes it into the page as base64; the page calls
`encrypt` / `decrypt` from `ssenc.browser.js` and returns the result; the Node side writes
it to `tests/out/`. Nothing in the page touches the file system, and no test logic lives
in the page — it only executes the library.

**SSH in the browser.** A browser cannot reach ssh-agent, so in the ssh cases the test
exposes one function to the page (`page.exposeFunction`) that forwards a sign request to
the test ssh-agent, and passes it as the `signer` option (5.1). Everything else — building
the challenge, deriving the key, unwrapping the slot, encrypting — runs in the browser.
The report labels these cells **ssh (bridged signer)** so it is clear what was and was not
exercised there.

### 8.4 Cases

A case = fixture × mode × key. One table in `tests/cases.ts` generates all of them, so
every stage and the report agree on what should exist.

| Group | Fixtures | Modes | Keys | Cases |
|---|---|---|---|---|
| Password, text and small binaries | 13 | lines ws=1, lines ws=0, blob | password | 39 |
| Password, large binaries (64 KiB – 1 MiB) | 4 | blob only | password | 4 |
| Key variety | 3 (plain text, tricky whitespace, small binary) | all 3 | ssh-ed25519, ssh-rsa, password + ssh-ed25519 (two slots, decrypted once with each key) | 27 |

70 cases × 5 producers = **350 encrypted files**; each is decrypted by 5 consumers, the
two-slot ones with both keys: **1,975 decrypt checks**. Large random binaries are not run
in lines mode: they would be thousands of lines of noise and take Bash minutes.

- Matrix cases use a deliberately cheap Argon2id setting through the normal `--kdf` option
  (`m=8 MiB, t=1, p=1`), otherwise the pure-TypeScript Argon2id dominates the run. The
  default and `strong` profiles are covered by one case per producer and by the vectors.
- Text fixtures stay under ~200 lines because of Bash's per-line cost; server stages run
  in parallel workers. Target: whole suite under 10 minutes in CI.

SSH cases start a private throwaway `ssh-agent` on a short socket path under `mktemp -d`,
load generated passphrase-protected test keys through `SSH_ASKPASS`, and kill the agent on
exit. They never touch the developer's own agent.

### 8.5 Extra suites (stage 4)

1. **Known-answer vectors** (`tests/vectors/`), every participant: primitive level (SIV,
   HKDF, Argon2id) and file level. Encryption is fully deterministic once a header is
   given, so a vector is `encrypt(fixture, key, previous = vector header) == expected bytes`.
   No test-only randomness hook is needed in production code.
2. **Rekey matrix**: encrypt with A, rekey with B, decrypt with C (5×5×5 on one fixture),
   both `rotateDataKey` settings; assert the old key no longer works. Includes
   password → ssh and ssh → password.
3. **Diff stability**: change one line, re-encrypt with `--previous` using a *different*
   participant, assert exactly one body line differs.
4. **Negative tests** with exact error kinds: wrong password (2), flipped bit in a token
   (2), truncated blob (2), swapped blob chunks (2), garbage header (3), ECDSA key (4),
   key missing from agent (4).
5. **Per-language unit tests** via `<lang>/test.sh` (`node --test`, `cargo test`, plain bash).

### 8.6 Result records

One JSON line per check:

```json
{"suite":"cross","case":"crlf.lines-ws1.password","fixture":"crlf","mode":"lines-ws1",
 "key":"password","producer":"bash","consumer":"browser-js","status":"pass",
 "ms":41,"expectedSha256":"…","actualSha256":"…","detail":""}
```

`status` is one of `pass`, `fail`, `skipped` (with the reason in `detail`), `missing`.
The report builder computes the expected set from `cases.ts` × participants, so a check
that never ran shows up as **missing and counts as a failure**. A crashed stage cannot
produce a green report. `tests/run.sh` exits non-zero if anything is `fail` or `missing`.

### 8.7 Report

One static, self-contained `index.html` (data embedded, no framework, also opens from
`file://` after a local run). It is meant to be explored, not just read: every number is
clickable down to the individual check, filters combine (OS · suite · key · mode ·
producer · consumer · status), a search box finds a case by name, and the current filter
state is kept in the URL so a specific view or failure can be linked. Light and dark
theme, usable on a phone. Top to bottom:

**1. Run header** — commit, branch, date, link to the CI run, OS, versions of node, rustc,
bash, openssl, OpenSSH and the browser, and totals.

```
commit 3f2a91c · main · 2026-11-21 14:02 UTC · ubuntu-24.04 · run #57
2,100 checks   2,097 pass   3 fail   0 skipped   0 missing          [ FAILED ]
```

**2. Where it was encrypted × where it was decrypted** — the main view. Rows are
producers, columns are consumers, each cell shows passed/total and is green only at 100%.

```
                        decrypted by →
encrypted by ↓     rust     bash     node-ts   node-js   browser-js
rust              84/84    84/84     84/84     84/84      84/84
bash              84/84    84/84     84/84     84/84      81/84 ✗
node-ts           84/84    84/84     84/84     84/84      84/84
node-js           84/84    84/84     84/84     84/84      84/84
browser-js        84/84    84/84     84/84     84/84      84/84
```

Filter chips above it narrow the same matrix: key (password · ssh-ed25519 · ssh-rsa ·
two-slot) and mode (lines ws=1 · lines ws=0 · blob). So "does ssh-rsa written by the
browser decrypt in bash?" is one click.

**3. Failures first** — every failed or missing check listed in full: case, producer →
consumer, expected and actual hash, error kind and stderr, link to the artifact file.
Empty when the run is green.

**4. Case grid** — one row per case, 25 narrow columns (producer → consumer pairs, grouped
by producer), one coloured square per check. Shows at a glance whether a failure follows a
fixture (a row is red), a producer (a column group is red) or a consumer (the same column
in every group is red). Clicking a cell in the matrix above scrolls to and highlights its
column here.

**5. Other suites** — vectors (participant × vector), rekey (A → B → C, shown as one 5×5
table per rekeying participant), diff stability, negative tests (participant × test, with
the error kind returned).

**6. Timings** — encrypt and decrypt time per participant, so regressions and the cost of
the Bash and browser implementations stay visible.

`results.json` and the artifacts of failed checks are published next to the page.

### 8.8 CI and GitHub Pages

**GitHub Actions is where the tests officially run.** Every suite in this plan runs
there on every push and pull request — per-language unit tests, vectors, both encrypt
stages (server and Playwright), the all×all decrypt stage, rekey, diff stability and
negative tests — and all of them land in the same published report. Per-language unit test
results (`cargo test`, `node --test`, bash) are converted to the same result records, so
the page is the single place to see everything. Running locally with `./test.sh` is the
same pipeline and produces the same page under `tests/out/report/`.

`.github/workflows/test.yml`:

1. `test` job, matrix over `ubuntu-latest` and `macos-latest` (Windows added in M7):
   `install.sh` → `envverify.sh` → `compile.sh` → `tests/run.sh`. Uploads `tests/out/` as
   a workflow artifact even when tests fail.
2. `report` job: downloads the results of all OS jobs and builds one site with an OS
   switch at the top of the page.
3. `deploy` job, **only on pushes to `main`**: `actions/upload-pages-artifact` +
   `actions/deploy-pages` → `https://stopsopa.github.io/encrypt/`. It runs when tests fail
   too, so the page always shows the true state of `main`; the workflow itself still ends
   red. Pull requests get the same report as a downloadable artifact, not on Pages.

Pages shows the latest run of `main` only. Older runs stay available as workflow artifacts
for GitHub's retention period.

### 8.9 The three scripts

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
| typescript | node ≥ 22.18 (native type stripping), npm, `node_modules` present | `npm ci` | typecheck, build the node and browser single files, transpile each |
| rust | cargo, rustc ≥ pinned MSRV, registry reachable or vendored | `cargo fetch --locked` | `cargo build --release --locked` |
| bash | bash ≥ 4, openssl with Argon2id + CTR + HMAC (functional probe), ssh-keygen `-Y`, xxd, base64, shellcheck (warn only) | prints package-manager command for anything missing; installs nothing silently | `bash -n`, shellcheck |
| tests | every server participant answers `ssenc --version`, `dist/ssenc.browser.js` exists, Playwright + Chromium installed, ssh-agent, ssh-add | `npm ci`, `npx playwright install chromium` | — |

---

## 9. Milestones

| # | Deliverable | Done when |
|---|---|---|
| M0 | `SPEC.md` + hand-computed primitive vectors | Spec reviewed; vectors reproduced by a throwaway script |
| M1 | Rust library + CLI, password mode, lines + blob | Rust passes vectors and its own round trips; becomes the reference |
| M2 | `tests/` stages 1, 3, 5, fixtures, report page, `envverify/install/compile/test.sh` skeleton, CI workflow publishing to Pages | 1×1 matrix visible on GitHub Pages |
| M3 | TypeScript node + browser single files (`.ts` and `.js` each) + CLI, Playwright stages | 4×4 matrix green (rust, node-ts, node-js, browser-js) |
| M4 | Bash library + CLI | 5×5 matrix green |
| M5 | SSH-agent slots in all participants, bridged signer for the browser | ssh cases green on mac + Linux |
| M6 | `rekey`, multi-slot, `--seal`, negative tests | Full suite green |
| M7 | Windows added to the CI matrix (Git Bash for the bash participant) | Green on all three OSes |
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
7. **Browsers in the matrix**: Chromium only (proposed) vs. also Firefox and WebKit as
   extra participants. Each has its own WebCrypto implementation, so it is real coverage,
   at the cost of a 7×7 matrix and a longer run.
8. **Cross-OS decrypt** (artifacts encrypted on macOS decrypted on Linux and the reverse):
   not in the plan; possible later because artifacts are already uploaded as files.

---

## 13. What changed during implementation

| Plan | What was built | Why |
|---|---|---|
| Vendor `@noble/hashes` Argon2id into the TypeScript file | Own Argon2id + BLAKE2b, about 250 lines | A real single `.ts` file needs sources that concatenate cleanly; adapting a multi-module library meant forking it anyway. Output is verified against OpenSSL for many parameter sets and against the shared vectors in all three languages. Default cost takes about 1.3 s in Node |
| Transpile with esbuild | TypeScript compiler `transpileModule` | One dev dependency less |
| Playwright spec files for the browser stages | The browser is one more participant of the same runner (`tests/lib/participants.ts`), driven with the Playwright library | Rekey and diff chains go through several participants (A encrypts, B rekeys, C decrypts); one runner keeps them uniform |
| 16 fixtures, 75 cases | 17 fixtures, 70 cases | Large binaries only in blob mode (section 8.4) |
| Fixture files committed | Generated deterministically at test time into `tests/out/fixtures/` | Avoids megabytes of random bytes in git |
| Test ssh keys generated at test time | Fixed test keys committed in `tests/keys/` (passphrase `ssenc-test`) | Known-answer vectors for ssh slots need stable keys |
| — | `encrypt … --chunk N`, `--fresh`, `decryptToString` (TypeScript) | Needed for vectors with small chunks, for overwriting a file made with another key, and convenience |
| — | `scripts/verify-lib.sh`, `xx.ts`, `.tool-versions` | Shared envverify output format, command menu, pinned Node.js |
| Windows in CI (M7) | Not done | Could not be tested here; the Windows agent pipe code is written but unverified |
