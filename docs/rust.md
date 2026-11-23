# ssenc — Rust library and binary

The crate lives in [`rust/`](../rust). It builds a library (`ssenc`) and a command-line
binary (`ssenc`). Rust ≥ 1.89.

Other documents: [command line](cli.md) · [TypeScript library](typescript.md) · [format specification](../SPEC.md)

## Getting it

The crate is not published on crates.io. Use it from git or from a local clone:

```toml
# Cargo.toml
[dependencies]
ssenc = { git = "https://github.com/stopsopa/encrypt" }
# or, from a clone:  ssenc = { path = "../encrypt/rust" }
```

To build the binary:

```sh
rust/install.sh     # cargo fetch --locked
rust/compile.sh     # cargo build --release --locked  ->  rust/target/release/ssenc
rust/bin/ssenc --version
```

`rust/bin/ssenc` is a small wrapper that runs the release binary. The command line itself
is described in [cli.md](cli.md).

## Quick start

```rust
use ssenc::{decrypt, encrypt, EncryptOptions, Key};

fn main() -> Result<(), ssenc::Error> {
    let key = Key::password("correct horse battery staple");

    // text -> ASCII text, one encrypted line per input line
    let encrypted: String = encrypt(b"host: db.internal\nport: 5432\n", &[key.clone()], &EncryptOptions::default())?;

    // back to the original bytes
    let plain: Vec<u8> = decrypt(encrypted.as_bytes(), &key)?;
    assert_eq!(plain, b"host: db.internal\nport: 5432\n");
    Ok(())
}
```

All functions are synchronous and return `Result<_, ssenc::Error>`.

## Functions

### `encrypt(input: &[u8], keys: &[Key], opts: &EncryptOptions) -> Result<String, Error>`

Encrypts `input`. With several keys the result can be opened with any one of them. Returns
7-bit ASCII text.

`EncryptOptions` (every field is an `Option`; `None` means the default — or, when
`previous` is given, "as in `previous`"). Build it with struct update syntax:

```rust
let opts = EncryptOptions { mode: Some(Mode::Blob), ..Default::default() };
```

| Field | Type | Default | Meaning |
|---|---|---|---|
| `mode` | `Option<Mode>` | `Mode::Lines` | `Lines`: every input line becomes one encrypted line. `Blob`: the input is encrypted as a whole (binary data, or when the line structure must not show). `Auto`: what `detect_mode(input)` says; with `previous`, the mode of `previous`. |
| `preserve_whitespace` | `Option<bool>` | `true` | Lines mode: leading and trailing spaces/tabs of each line stay as they are. `false` encrypts the whole line. Line endings are always kept. |
| `pad` | `Option<u64>` (0–4096) | `16` | Lines mode: pad each line to a multiple of this many bytes, so the encrypted length reveals only a size bucket. `0` disables. |
| `chunk` | `Option<u64>` (1–1048576) | `65536` | Blob mode: chunk size in bytes. |
| `kdf` | `Option<Kdf>` | `KdfParams::DEFAULT` | Argon2id cost for password keys, see below. |
| `previous` | `Option<Vec<u8>>` | — | An earlier encrypted version of the same data. Its data key and key slots are reused, so every unchanged line encrypts to the identical text. One of the given keys must open it. |
| `seal` | `Option<bool>` | `false` | Lines mode: add a checksum over the whole file, so removed, added or reordered lines are detected on decrypt. |

```rust
use ssenc::{encrypt, EncryptOptions, Key, Mode};

let key = Key::password("pw");

// binary data
let enc = encrypt(&bytes, &[key.clone()], &EncryptOptions { mode: Some(Mode::Blob), ..Default::default() })?;

// stable diffs: re-encrypt after an edit, reusing the previous output
let v1 = encrypt(b"a\nb\nc\n", &[key.clone()], &EncryptOptions::default())?;
let v2 = encrypt(b"a\nCHANGED\nc\n", &[key.clone()],
    &EncryptOptions { previous: Some(v1.clone().into_bytes()), ..Default::default() })?;
// v1 and v2 differ in exactly one line
```

Without `previous` a new random data key is generated, so encrypting the same input twice
gives completely different output.

### `decrypt(input: &[u8], key: &Key) -> Result<Vec<u8>, Error>`

Returns the original bytes. The mode and all parameters are read from the text itself.
Nothing is returned when authentication fails.

### `rekey(input: &[u8], old_key: &Key, new_keys: &[Key], opts: &RekeyOptions) -> Result<String, Error>`

Replaces the keys of an encrypted text. All previous keys stop working.

| Field of `RekeyOptions` | Default | Meaning |
|---|---|---|
| `rotate_data_key: bool` | `true` | `true`: decrypt and encrypt again under a new data key (every line changes once). `false`: only the key slot lines are replaced and the body stays byte-identical — cheap, but someone who has the old key and an old copy can still read later versions. |
| `kdf: Option<Kdf>` | `KdfParams::DEFAULT` | Argon2id cost for the new password keys. |

```rust
use ssenc::{rekey, Key, RekeyOptions};
let rotated = rekey(encrypted.as_bytes(), &Key::password("old"), &[Key::password("new")], &RekeyOptions::default())?;
```

### `inspect(input: &[u8]) -> Result<InspectResult, Error>`

Needs no key. Describes an encrypted text:

```rust
pub enum InspectResult {
    Lines { ws: bool, pad: usize, seal: bool, slots: Vec<SlotInfo> },
    Blob { chunk: usize, slots: Vec<SlotInfo> },
}
pub enum SlotInfo {
    Pw { m: u32, t: u32, p: u32 },
    Ssh { key_type: String, fingerprint: String },
}
```

`InspectResult::to_json()` gives the one-line JSON that `ssenc inspect` prints.

### `detect_mode(input: &[u8]) -> Mode`

What `Mode::Auto` picks: `Mode::Lines` when the input is text, which means it has no NUL
byte and is valid UTF-8 (an empty input is text), otherwise `Mode::Blob`. The whole input
is examined. A wrong guess never loses data, both modes take any bytes.

```rust
use ssenc::{detect_mode, encrypt, EncryptOptions, Mode};

assert_eq!(detect_mode(b"host: db\n"), Mode::Lines);
assert_eq!(detect_mode(&[0x89, b'P', b'N', b'G', 0]), Mode::Blob);
let enc = encrypt(&bytes, &keys, &EncryptOptions { mode: Some(Mode::Auto), ..Default::default() })?;
```

`Mode::Auto` exists only as an option of `encrypt`; an encrypted file is always `Lines`
or `Blob`.

### SSH helpers

| Function | Returns |
|---|---|
| `ssh_parse_public_key(text: &str)` | `Result<Vec<u8>, Error>`: the key blob from the content of a `.pub` file |
| `ssh_fingerprint(blob: &[u8])` | `String`: `SHA256:…` as printed by `ssh-keygen -l` |
| `ssh_key_type(blob: &[u8])` | `Result<String, Error>`, e.g. `"ssh-ed25519"` |

`ssenc::VERSION` is the crate version.

## Keys

```rust
pub enum Key {
    Password { password: Vec<u8> },
    Ssh {
        public_key: Option<String>,    // content of a .pub file
        fingerprint: Option<String>,   // "SHA256:…" of a key loaded in ssh-agent
        agent_socket: Option<String>,  // default: $SSH_AUTH_SOCK
        signer: Option<SshSigner>,     // replaces ssh-agent
    },
}
```

Constructors:

| Constructor | Key |
|---|---|
| `Key::password("…")` | password (raw bytes, nothing trimmed or normalised, must not be empty) |
| `Key::ssh_public_key(text)` | ssh key given as the content of its `.pub` file |
| `Key::ssh_fingerprint("SHA256:…")` | ssh key loaded in the agent, found by fingerprint |

The private key must be loaded in `ssh-agent`: the library asks the agent for a signature
and derives the key from it, so the private key never reaches this code. Supported:
`ssh-ed25519` and `ssh-rsa`. ECDSA and hardware (`sk-…`) keys are refused because their
signatures are different every time.

```rust
let pubkey = std::fs::read_to_string("/home/me/.ssh/id_ed25519.pub").expect("public key");
let key = Key::ssh_public_key(pubkey);
let enc = encrypt(b"secret\n", &[Key::password("backup"), key], &EncryptOptions::default())?;
```

`signer` replaces the agent: it gets the public key blob and the data to sign and must
return the signature blob exactly as an ssh-agent would (for `ssh-rsa` with algorithm
`rsa-sha2-512`).

```rust
pub type SshSigner = Arc<dyn Fn(&[u8], &[u8]) -> Result<Vec<u8>, Error> + Send + Sync>;
```

## Argon2id cost

```rust
pub struct KdfParams { pub m: u32, pub t: u32, pub p: u32 }   // m in KiB
KdfParams::DEFAULT   // m = 65536 (64 MiB), t = 3, p = 4
KdfParams::STRONG    // m = 1048576 (1 GiB), t = 4, p = 4

pub enum Kdf { Profile(String), Params(KdfParams) }
// both convert with .into():
let a: Kdf = "strong".into();              // "default", "strong" or "m=..,t=..,p=.."
let b: Kdf = KdfParams { m: 262144, t: 3, p: 4 }.into();
```

The cost is stored in the encrypted text, so decrypting needs no setting.

## Errors

```rust
pub struct Error { pub kind: ErrorKind, pub message: String }
pub enum ErrorKind { Usage, Auth, Malformed, Env }
```

| `ErrorKind` | When | `exit_code()` |
|---|---|---|
| `Usage` | bad option value, empty password, no key | 1 |
| `Auth` | the key does not open the text, or the text was modified | 2 |
| `Malformed` | the input is not valid ssenc1 text | 3 |
| `Env` | ssh-agent unreachable, key not loaded, unsupported key type | 4 |

```rust
match ssenc::decrypt(text.as_bytes(), &key) {
    Ok(plain) => { /* … */ }
    Err(e) if e.kind == ssenc::ErrorKind::Auth => eprintln!("wrong password"),
    Err(e) => return Err(e),
}
```

`Error` implements `std::error::Error` and `Display`.

## Notes

- `ssenc::prim` (`hkdf32`, `SivKey`, `argon2id`) is public only so the test vectors can
  reach it. It is not a stable interface.
- Windows: the code for the OpenSSH agent pipe (`\\.\pipe\openssh-ssh-agent`) is written
  but has not been compiled or tested.
- Text produced by this crate can be decrypted by the TypeScript and Bash implementations
  and the other way round; that is tested for every pair on every push
  ([report](https://stopsopa.github.io/encrypt/)).
