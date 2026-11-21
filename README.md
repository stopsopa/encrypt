# ssenc

Password / ssh-agent encryption of text and binary files into **diff-friendly ASCII text**,
with three interoperable implementations: **TypeScript**, **Rust** and **Bash**.

Made for keeping encrypted files in git: in line mode every line is encrypted on its own,
so when one line of the plaintext changes, exactly one line of the encrypted file changes.

```
plain                       encrypted
----------------------      ------------------------------------------------
server:                     #ssenc1 lines ws=1 pad=16
    host: db.internal       #slot pw argon2id m=65536,t=3,p=4 os3aSYtR… 2y0CzoI8…
    port: 5432              PqXYBv6DPJHnspY2ZLnfpvTlwrVyJyqG3W-7CM1mISE
                                5DoEJCK0j5aaC4fNti2JC_jz5LeQS9rGzzL1ESoKSQntIaD_jpFlzQ…
                                QcTY1sI009UgXjWCZuwOwNikpQhBIdWbf9wVNCkpk-w
```

- Format specification: [SPEC.md](SPEC.md) · design and rationale: [PLAN.md](PLAN.md)
- Test report (every implementation decrypting every other one, including a browser):
  <https://stopsopa.github.io/encrypt/>

## What it does

| | |
|---|---|
| Password | Argon2id → key. Cost parameters are stored in the file. |
| Cipher | AES-256-CTR + HMAC-SHA-256 in SIV composition: authenticated and deterministic. |
| Lines mode | Line by line. Leading/trailing spaces and tabs stay in clear (optional), line endings are kept. |
| Blob mode | Any bytes, 64 KiB authenticated chunks, base64url wrapped at 76 columns. |
| SSH key | Key derived from a signature made by `ssh-agent` (Ed25519 or RSA). The private key never leaves the agent. |
| Several keys | A file can have several key slots, e.g. your ssh key and a backup password. |
| Rekey | Replace the keys, either re-encrypting everything or only rewrapping the data key. |

## Command line

Every implementation has the same CLI: `rust/bin/ssenc`, `typescript/bin/ssenc`, `bash/bin/ssenc`.

```sh
export SSENC_PASSWORD='…'                       # or --password-file F, or a prompt on a terminal

ssenc encrypt -i config.yml -o config.yml.enc   # lines mode
ssenc decrypt -i config.yml.enc -o config.yml
ssenc encrypt --mode blob -i photo.jpg -o photo.jpg.enc

# after editing config.yml: the existing output is reused, only changed lines differ
ssenc encrypt -i config.yml -o config.yml.enc

# ssh key (must be loaded in ssh-agent), optionally together with a password
ssenc encrypt --ssh-key ~/.ssh/id_ed25519.pub -i config.yml -o config.yml.enc
ssenc decrypt --ssh-key ~/.ssh/id_ed25519.pub -i config.yml.enc

# change the key
SSENC_NEW_PASSWORD='…' ssenc rekey -i config.yml.enc -o config.yml.enc
ssenc inspect -i config.yml.enc                 # mode and key slots, no key needed
```

Options: `--no-preserve-ws`, `--pad N`, `--chunk N`, `--kdf default|strong|m=..,t=..,p=..`,
`--seal`, `--previous FILE`, `--fresh`, `--rewrap-only`. Exit codes: 1 usage, 2 wrong key
or modified data, 3 malformed input, 4 environment (ssh-agent, unsupported key).
Full description in [SPEC.md](SPEC.md) section 7.

## Libraries

Same four operations everywhere: `encrypt`, `decrypt`, `rekey`, `inspect`.

**TypeScript** — one file, no dependencies, ES module. Copy the one you need from
[`typescript/dist/`](typescript/dist):

| File | For |
|---|---|
| `ssenc.node.ts` / `ssenc.node.js` | Node.js ≥ 20 (password and ssh-agent) |
| `ssenc.browser.ts` / `ssenc.browser.js` | browsers (password; ssh only with your own `signer`) |

```ts
import { encrypt, decrypt, rekey, inspect } from "./ssenc.node.ts";

const key = { type: "password", password: "…" } as const;
const enc = await encrypt("host: db\nport: 5432\n", key);            // string (ASCII)
const next = await encrypt("host: db\nport: 6543\n", key, { previous: enc }); // one line differs
const plain = await decrypt(next, key);                               // Uint8Array
await encrypt(bytes, { type: "ssh", publicKey: pubFileContent }, { mode: "blob" });
```

Options of `encrypt`: `mode`, `preserveWhitespace`, `pad`, `chunk`, `kdf`, `previous`, `seal`.

**Rust** — crate in [`rust/`](rust): `ssenc::encrypt`, `decrypt`, `rekey`, `inspect`.

**Bash** — `source bash/ssenc.sh`, then `ssenc_encrypt`, `ssenc_decrypt`, `ssenc_rekey`,
`ssenc_inspect` (stdin → stdout). Needs bash ≥ 4 and OpenSSL ≥ 3.2.

## What you should know before relying on it

- **Lines mode shows structure on purpose**: number of lines, indentation, blank lines,
  rough line lengths, and which lines of one file are identical. Use blob mode when that
  is too much.
- **Lines mode does not notice removed or reordered lines** unless `--seal` is used (and a
  sealed file conflicts on every concurrent git merge).
- **Stable diffs need the previous encrypted file** (`--previous`, or simply writing to
  the same output file). Without it a new data key is made and every line changes.
- **The Bash implementation is slow and less private**: roughly 15–20 ms per line, and
  `openssl` receives keys as command-line arguments, visible to other processes on the
  same machine while it runs. Prefer the Rust CLI on shared machines.
- **SSH mode**: anyone who can make your agent sign can derive the key, so do not use it
  with agent forwarding to hosts you do not trust. ECDSA and hardware (`sk-`) keys are
  refused because their signatures are not repeatable. Add a password slot as a backup.
- The cipher construction is built from standard primitives but is specific to this
  project and has **not been independently audited**.

## Development

Node.js version is pinned in `.tool-versions` (asdf); CI uses the same file.

```sh
./install.sh      # dependencies of every part
./compile.sh      # build all implementations
./envverify.sh    # is everything needed present? reports every problem with a fix
./test.sh         # unit tests + cross matrix incl. browser, builds tests/out/report/index.html
```

Each of `typescript/`, `rust/`, `bash/` has its own `envverify.sh`, `install.sh`,
`compile.sh`, `test.sh`. All of them are also in the [`xx`](https://github.com/stopsopa/xx)
menu (`xx.ts`): `xx test`, `xx rust compile`, `xx report open`, …

Tests encrypt every case with every participant (Rust, Bash, Node running the `.ts`,
Node running the `.js`, and the browser build in headless Chromium), save the results to
files, then decrypt every file with every participant. The ssh tests use a private
throwaway `ssh-agent` with the test keys in `tests/keys/`; your own agent is never used.
