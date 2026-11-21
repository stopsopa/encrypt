# ssenc — TypeScript / JavaScript library

One file, no dependencies, ES module. Pick the build for where the code runs and copy that
single file into your project (or import it straight from a clone of this repository).

| File | Runs in | Password keys | SSH keys |
|---|---|---|---|
| [`typescript/dist/ssenc.node.ts`](../typescript/dist/ssenc.node.ts) | Node.js ≥ 22.18 (runs `.ts` directly), Deno, Bun | yes | yes, through `ssh-agent` |
| [`typescript/dist/ssenc.node.js`](../typescript/dist/ssenc.node.js) | Node.js ≥ 20 | yes | yes, through `ssh-agent` |
| [`typescript/dist/ssenc.browser.ts`](../typescript/dist/ssenc.browser.ts) | bundlers / TypeScript projects targeting browsers | yes | only with your own `signer` |
| [`typescript/dist/ssenc.browser.js`](../typescript/dist/ssenc.browser.js) | browsers, web workers | yes | only with your own `signer` |

All four export exactly the same names and types. The `.js` files are the `.ts` files with
the types removed. The files are generated from `typescript/src/` by `typescript/compile.sh`;
do not edit them.

Other documents: [command line](cli.md) · [Rust library](rust.md) · [format specification](../SPEC.md)

## Quick start

```ts
import { encrypt, decrypt, decryptToString } from "./ssenc.node.ts";

const key = { type: "password", password: "correct horse battery staple" } as const;

// text -> ASCII text, one encrypted line per input line
const encrypted = await encrypt("host: db.internal\nport: 5432\n", key);

// back to the original
const text = await decryptToString(encrypted, key);   // string
const bytes = await decrypt(encrypted, key);          // Uint8Array
```

In a browser:

```html
<script type="module">
  import { encrypt, decryptToString } from "./ssenc.browser.js";
  const key = { type: "password", password: "…" };
  const encrypted = await encrypt("hello", key);
  console.log(await decryptToString(encrypted, key));
</script>
```

The browser build needs a secure context (`https://` or `localhost`) because it uses
WebCrypto, and an ES module cannot be loaded from `file://`.

Every function is `async` (WebCrypto is asynchronous) except `inspect`.

## Functions

### `encrypt(input, key, options?) → Promise<string>`

| Parameter | Type | Meaning |
|---|---|---|
| `input` | `Uint8Array \| string` | What to encrypt. A string is encoded as UTF-8. |
| `key` | `Key \| Key[]` | One key, or several: the result can then be opened with any one of them. |
| `options` | `EncryptOptions` | See below. All optional. |

Returns the encrypted text: 7-bit ASCII, safe to store in a text file or a URL.

`EncryptOptions`:

| Option | Type | Default | Meaning |
|---|---|---|---|
| `mode` | `"lines" \| "blob"` | `"lines"` | `lines`: every input line becomes one encrypted line. `blob`: the input is encrypted as a whole (use for binary data, or when the line structure must not show). |
| `preserveWhitespace` | `boolean` | `true` | Lines mode: leading and trailing spaces/tabs of each line stay as they are, only what is between them is encrypted. `false` encrypts the whole line. Line endings are always kept. |
| `pad` | `number` (0–4096) | `16` | Lines mode: each line is padded to a multiple of this many bytes before encryption, so the encrypted length reveals only a size bucket. `0` disables. |
| `chunk` | `number` (1–1048576) | `65536` | Blob mode: chunk size in bytes. |
| `kdf` | `"default" \| "strong" \| "m=..,t=..,p=.." \| { m, t, p }` | `"default"` | Argon2id cost for password keys. `default` = 64 MiB, 3 passes, 4 lanes; `strong` = 1 GiB, 4 passes. `m` is in KiB. |
| `previous` | `Uint8Array \| string` | — | An earlier encrypted version of the same data. Its data key and key slots are reused, so every unchanged line encrypts to the identical text. The given key must open it. Options not given are taken from it. |
| `seal` | `boolean` | `false` | Lines mode: add a checksum over the whole file, so removed, added or reordered lines are detected on decrypt. |

```ts
// binary data
const enc = await encrypt(fileBytes, key, { mode: "blob" });

// stable diffs: re-encrypt after an edit, reusing the previous output
const v1 = await encrypt("a\nb\nc\n", key);
const v2 = await encrypt("a\nCHANGED\nc\n", key, { previous: v1 });
// v1 and v2 differ in exactly one line

// two keys: either one opens it
const enc2 = await encrypt(text, [
  { type: "password", password: "backup password" },
  { type: "ssh", publicKey: readFileSync(homedir() + "/.ssh/id_ed25519.pub", "utf8") },
]);
```

Without `previous` a new random data key is generated, so encrypting the same input twice
gives completely different output.

### `decrypt(input, key) → Promise<Uint8Array>`

`input` is the encrypted text (`string` or `Uint8Array`), `key` is a single `Key`. Returns
the original bytes. The mode and all parameters are read from the text itself.

### `decryptToString(input, key) → Promise<string>`

Same as `decrypt`, decoded as UTF-8. Use it when the original was text.

### `rekey(input, oldKey, newKey, options?) → Promise<string>`

Replaces the keys of an encrypted text. `oldKey` must open it; `newKey` is a `Key` or
`Key[]`. All previous keys stop working.

| Option | Default | Meaning |
|---|---|---|
| `rotateDataKey` | `true` | `true`: decrypt and encrypt again under a new data key (every line changes once). `false`: only the key slot lines are replaced and the body stays byte-identical — cheap, but someone who has the old key and an old copy can still read later versions. |
| `kdf` | `"default"` | Argon2id cost for the new password keys. |

```ts
const rotated = await rekey(encrypted, { type: "password", password: "old" },
                                       { type: "password", password: "new" });
```

### `inspect(input) → InspectResult`

Synchronous, needs no key. Describes an encrypted text:

```ts
inspect(encrypted);
// { format: "ssenc1", mode: "lines", ws: true, pad: 16, seal: false,
//   slots: [ { type: "pw", kdf: "argon2id", m: 65536, t: 3, p: 4 } ] }
// blob:  { format: "ssenc1", mode: "blob", chunk: 65536, slots: [...] }
// ssh slot: { type: "ssh", keyType: "ssh-ed25519", fingerprint: "SHA256:…" }
```

### `setKdfCacheSize(entries)`

Off by default (`0`). With a positive number the library keeps that many Argon2id results
in memory, so repeated operations with the same password and the same encrypted text skip
the expensive key derivation (about 1.3 s at the default cost). Meant for interactive pages
that re-encrypt on every change; derived keys stay in memory while cached. `setKdfCacheSize(0)`
clears the cache.

### SSH helpers

| Function | Returns |
|---|---|
| `sshParsePublicKey(text)` | the key blob (`Uint8Array`) from the content of a `.pub` file |
| `sshFingerprint(blob)` | `Promise<string>`: `SHA256:…` as printed by `ssh-keygen -l` |
| `sshKeyType(blob)` | e.g. `"ssh-ed25519"` |

### Constants

`VERSION` (e.g. `"0.1.0"`) and `BUILD` (`"node"` or `"browser"`).

## Keys

```ts
type Key = PasswordKey | SshKey;

type PasswordKey = { type: "password"; password: string | Uint8Array };

type SshKey = {
  type: "ssh";
  publicKey?: string;     // content of a .pub file: "ssh-ed25519 AAAA… comment"
  fingerprint?: string;   // "SHA256:…" of a key loaded in ssh-agent (Node build)
  agentSocket?: string;   // default: $SSH_AUTH_SOCK (Node build)
  signer?: SshSigner;     // replaces ssh-agent; required in the browser build
};
```

**Password.** Used as raw bytes (a string is UTF-8 encoded); nothing is trimmed or
normalised. Must not be empty.

**SSH key (Node build).** Give `publicKey` or `fingerprint`. The private key must be loaded
in `ssh-agent`; the library asks the agent for a signature and derives the key from it, so
the private key never reaches this code. Supported: `ssh-ed25519` and `ssh-rsa`. ECDSA and
hardware (`sk-…`) keys are refused because their signatures are different every time.

```ts
import { readFileSync } from "node:fs";
const key = { type: "ssh", publicKey: readFileSync("/home/me/.ssh/id_ed25519.pub", "utf8") } as const;
const enc = await encrypt("secret\n", key);
```

**SSH key with your own signer.** `signer` receives the public key blob and the data to
sign and must return the signature blob exactly as an ssh-agent would
(`string(algorithm) || string(signature)`; for `ssh-rsa` the algorithm must be
`rsa-sha2-512`). With a signer, `publicKey` is required.

```ts
type SshSigner = (publicKeyBlob: Uint8Array, data: Uint8Array) => Promise<Uint8Array>;
```

## Errors

Every failure is an `SsencError` with a `kind`:

| `kind` | When |
|---|---|
| `"USAGE"` | bad option value, empty password, no key |
| `"AUTH"` | the key does not open the text, or the text was modified |
| `"MALFORMED"` | the input is not valid ssenc1 text |
| `"ENV"` | ssh-agent unreachable, key not loaded, unsupported key type, missing signer |

```ts
import { SsencError } from "./ssenc.node.ts";
try {
  await decrypt(encrypted, key);
} catch (e) {
  if (e instanceof SsencError && e.kind === "AUTH") console.log("wrong password");
  else throw e;
}
```

Nothing is returned when authentication fails: you never get partially decrypted data.

## Practical notes

- **Cost of a password operation.** Each `encrypt`, `decrypt` or `rekey` with a password
  runs Argon2id once per password slot tried: about 1.3 s at the default cost, and it blocks
  the thread while it runs. In a page, call the library from a web worker (see
  [`encryptor/worker.js`](../encryptor/worker.js)) and consider `setKdfCacheSize`.
- **Types.** The `.ts` files use only erasable TypeScript syntax, so Node can run them
  without a build step and any bundler can consume them. With the `.js` files you get no
  type declarations; import the `.ts` file in TypeScript projects.
- **Same output everywhere.** Text produced by this library can be decrypted by the Rust
  and Bash implementations and the other way round; that is tested for every pair on every
  push ([report](https://stopsopa.github.io/encrypt/)).
