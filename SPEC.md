# ssenc1 format specification

Normative. Every implementation in this repository must produce and accept exactly this.
`||` is byte concatenation. `u64be(n)` is 8 bytes big-endian. `b64url(x)` is RFC 4648 §5
base64url **without** `=` padding; a reader rejects characters outside the alphabet and
lengths of 4n+1, but does not have to reject non-zero unused trailing bits (the decoded
bytes are authenticated anyway). All strings below are ASCII bytes without terminator.

## 1. Primitives

### 1.1 HKDF32

```
HKDF32(ikm, salt, info) = HMAC-SHA-256(key = PRK, info || 0x01)        (32 bytes)
                    PRK = HMAC-SHA-256(key = salt, ikm)
```

This is RFC 5869 HKDF-SHA-256 with a 32-byte output. When `salt` is "none" below it is
32 zero bytes.

### 1.2 SIV

```
SIV-Encrypt(Kmac, Kenc, ad, pt):
    tag = HMAC-SHA-256(Kmac, u64be(len(ad)) || ad || pt)[0..16]
    iv  = tag;  iv[8] &= 0x7f;  iv[12] &= 0x7f
    ct  = AES-256-CTR(key = Kenc, counter block = iv, pt)     (128-bit big-endian counter)
    return tag || ct                                          (len(pt) + 16 bytes)

SIV-Decrypt(Kmac, Kenc, ad, in):
    require len(in) >= 16, else MALFORMED
    tag = in[0..16]; ct = in[16..]
    iv as above; pt = AES-256-CTR(Kenc, iv, ct)
    require constant-time-equal(tag, HMAC-SHA-256(Kmac, u64be(len(ad)) || ad || pt)[0..16]),
        else AUTH
    return pt
```

### 1.3 Subkeys

From a 32-byte data key `DEK`:

```
K_line_mac = HKDF32(DEK, none, "ssenc1/line-mac")
K_line_enc = HKDF32(DEK, none, "ssenc1/line-enc")
K_blob_mac = HKDF32(DEK, none, "ssenc1/blob-mac")
K_blob_enc = HKDF32(DEK, none, "ssenc1/blob-enc")
K_seal     = HKDF32(DEK, none, "ssenc1/seal")
```

From a 32-byte key-encryption key `KEK`:

```
K_wrap_mac = HKDF32(KEK, none, "ssenc1/wrap-mac")
K_wrap_enc = HKDF32(KEK, none, "ssenc1/wrap-enc")
wrapped    = SIV-Encrypt(K_wrap_mac, K_wrap_enc, "ssenc1/slot", DEK)      (48 bytes)
```

## 2. File layout

```
header-line LF
slot-line LF            (one or more)
[seal-line LF]          (lines mode only, optional)
body
```

Header, slot and seal lines are always written with a single LF. A reader strips one
trailing CR from each of them if present. The header ends at the first line that does not
start with `#slot ` or `#seal `. Fields are separated by exactly one space.

### 2.1 Header line

```
#ssenc1 lines ws=<0|1> pad=<N>         0 <= N <= 4096
#ssenc1 blob chunk=<N>                 1 <= N <= 1048576
```

Numbers are decimal without leading zeros (except `0` itself). Defaults when encrypting:
`ws=1`, `pad=16`, `chunk=65536`.

### 2.2 Password slot

```
#slot pw argon2id m=<M>,t=<T>,p=<P> <b64url(salt)> <b64url(wrapped)>
```

- `salt`: 16 random bytes. `wrapped`: 48 bytes.
- `KEK = Argon2id(password, salt, memory = M KiB, iterations = T, parallelism = P,
  output = 32 bytes, version 0x13, no secret, no associated data)`.
- Password is the raw byte string; no normalisation. It must not be empty.
- A reader rejects (MALFORMED) parameters outside `8*P <= M <= 4194304`, `1 <= T <= 64`,
  `1 <= P <= 16`.
- KDF profiles when encrypting: `default` = `m=65536,t=3,p=4`; `strong` = `m=1048576,t=4,p=4`;
  or explicit `m=..,t=..,p=..`.

### 2.3 SSH slot

```
#slot ssh <keytype> <fingerprint> <b64url(salt)> <b64url(wrapped)>
```

- `keytype`: `ssh-ed25519` or `ssh-rsa`. Any other key type is refused (ENV error).
- `fingerprint`: `SHA256:` followed by standard base64 **without padding** of
  SHA-256(public key blob) — the form printed by `ssh-keygen -l`.
- `salt`: 32 random bytes.

```
message  = "ssenc1 ssh slot" || salt
signed   = "SSHSIG" || string("ssenc-v1@stopsopa") || string("") || string("sha512")
           || string(SHA-512(message))
sigblob  = signature blob returned by the agent for `signed`
           (= string(algorithm) || string(raw signature)); for ssh-rsa the request uses
           flag SSH_AGENT_RSA_SHA2_512 (4), so algorithm is "rsa-sha2-512"
KEK      = HKDF32(sigblob, salt, "ssenc1/ssh-kek")
```

`string(x)` is the SSH wire encoding: `u32be(len(x)) || x`. `sigblob` is byte-identical to
the `signature` field of the SSHSIG produced by
`ssh-keygen -Y sign -n ssenc-v1@stopsopa -f key.pub` over `message`.

### 2.4 Seal line (optional, lines mode)

```
#seal <b64url(HMAC-SHA-256(K_seal, header-line || 0x0a || body))>
```

`header-line` is the first line without its terminator; `body` is every byte after the LF
that ends the last header/slot/seal line. If a seal line is present a reader must verify
it (AUTH on mismatch) before returning any plaintext.

## 3. Lines mode body

The plaintext is a byte string; it need not be valid UTF-8.

1. Split into lines at each LF. The terminator of a line is `CR LF` if the byte before the
   LF is CR, otherwise `LF`. If the plaintext does not end with LF, the last line has an
   empty terminator. If it does end with LF there is no extra empty line. Empty plaintext
   has zero lines and an empty body.
2. For a line with content `L` (terminator removed):
   - `ws=1`: `lead` = longest prefix of `L` consisting of SP (0x20) and TAB (0x09);
     `trail` = longest such suffix of the rest; `core` = what is between.
     If `core` is empty, output `L` unchanged. Otherwise output `lead || token(core) || trail`.
   - `ws=0`: output `token(L)` (also when `L` is empty).
3. Append the line's original terminator unchanged.

```
token(x)  = b64url(SIV-Encrypt(K_line_mac, K_line_enc, "", padded(x)))
padded(x) = x                                     if pad = 0
          = x || 0x80 || 0x00 * k                 otherwise, smallest k >= 0 such that
                                                  the length is a multiple of pad
```

Decryption (same for `ws=0` and `ws=1`): split lines the same way; for each line strip
`lead` and `trail` as above; if `core` is empty output the line unchanged; otherwise
`core` must be valid unpadded base64url decoding to at least 16 bytes (else MALFORMED),
SIV-Decrypt it, and if `pad != 0` remove trailing 0x00 bytes then one 0x80 (MALFORMED if
that byte is not 0x80). Output `lead || plaintext || trail || terminator`.

## 4. Blob mode body

1. Split the plaintext into chunks of `chunk` bytes; the last chunk may be shorter. Empty
   plaintext is one empty chunk. A plaintext whose length is a multiple of `chunk` has no
   extra empty chunk.
2. `record_i = SIV-Encrypt(K_blob_mac, K_blob_enc, u64be(i) || final, chunk_i)` with `i`
   counted from 0 and `final` = 0x01 for the last chunk, 0x00 otherwise.
3. Body = `b64url(record_0 || record_1 || ...)` split into lines of 76 characters, each
   line (including the last) followed by LF.

Decryption: remove every CR, LF, SP and TAB from the body, base64url-decode (MALFORMED on
error or when the result is empty), split into records of `chunk + 16` bytes (the last may
be shorter), decrypt each with its index and `final` set only for the last record.

## 5. Operations

- **encrypt(plaintext, keys, options)** — generates a random DEK, one slot per key (password
  slots first, then ssh slots, each in the order given). With `previous` (an existing
  ssenc1 text): the first given key that opens `previous` yields its DEK (AUTH if none
  does); its slot lines are copied verbatim and no new slots are made; header options not
  given explicitly are taken from the `previous` header.
  Mode `auto` is not a third format, only a way to choose between the two: without
  `previous` the mode is `lines` when the plaintext contains no 0x00 byte and is
  well-formed UTF-8 (RFC 3629: no overlong forms, no surrogates, nothing above U+10FFFF;
  the empty plaintext counts as text), otherwise `blob`; the whole plaintext is examined.
  With `previous`, `auto` means the mode of `previous`. Test inputs:
  `tests/vectors/auto-mode.json`.
- **decrypt(text, key)** — a password is tried against every `pw` slot in order; an ssh key
  against every `ssh` slot whose fingerprint equals the key's. The first slot whose unwrap
  authenticates gives the DEK. No such slot → AUTH.
- **rekey(text, oldKey, newKeys, options)** — opens with `oldKey`. `rotateDataKey = true`
  (default): decrypt and encrypt again with a new DEK and new slots, keeping mode, `ws`,
  `pad`, `chunk` and the presence of a seal. `false`: only the slot lines are replaced by
  new slots wrapping the same DEK; the header line, seal and body are kept (header and seal
  lines are re-written with LF if they had CRLF).
- **inspect(text)** — one line of JSON followed by LF, keys in exactly this order:

```
{"format":"ssenc1","mode":"lines","ws":true,"pad":16,"seal":false,"slots":[<slot>,...]}
{"format":"ssenc1","mode":"blob","chunk":65536,"slots":[<slot>,...]}
<slot> = {"type":"pw","kdf":"argon2id","m":65536,"t":3,"p":4}
       | {"type":"ssh","keyType":"ssh-ed25519","fingerprint":"SHA256:..."}
```

## 6. Errors

| Kind | CLI exit code | When |
|---|---|---|
| USAGE | 1 | bad arguments, empty password, no key given |
| AUTH | 2 | no slot opens with the key; a tag or the seal does not verify |
| MALFORMED | 3 | not an ssenc1 file, bad header, bad base64, bad padding, out-of-range parameter |
| ENV | 4 | ssh-agent unreachable, key not in agent, unsupported key type, missing tool |

CLI errors are written to stderr as `ssenc: <KIND>: <message>`; nothing is written to the
output on error.

## 7. CLI

```
ssenc encrypt [--mode lines|blob|auto] [--no-preserve-ws] [--pad N] [--chunk N] [--kdf PROFILE]
              [--seal] [--previous FILE | --fresh] KEYS [-i IN] [-o OUT]
ssenc decrypt KEY [-i IN] [-o OUT]
ssenc rekey   KEY NEWKEYS [--kdf PROFILE] [--rewrap-only] [-i IN] [-o OUT]
ssenc inspect [-i IN]
ssenc --version                         prints "ssenc <implementation> <version>"

KEY / KEYS   --password-file F          file content minus one trailing LF or CRLF
             env SSENC_PASSWORD         used when no --password-file is given
             --ssh-key X                public key file, or SHA256:... fingerprint of a key
                                        in the agent; repeatable for encrypt
NEWKEYS      --new-password-file F | env SSENC_NEW_PASSWORD | --new-ssh-key X (repeatable)
```

- `-i` / `-o` default to stdin / stdout. The input is read completely before the output is
  opened, so `-i` and `-o` may name the same file.
- If no password source and no `--ssh-key` is given, stdin is a terminal and `-i` names a
  file, the password is prompted for on the terminal; otherwise USAGE.
- `--kdf` only affects slots that are created: it is ignored when `previous` supplies them.
- `decrypt` and the old key of `rekey` use exactly one key: `--ssh-key` if given, else the
  password.
- `encrypt`: if `--previous` is not given, `--fresh` is not given, and `-o` names an
  existing file that starts with `#ssenc1 `, that file is used as `previous`.
- `PROFILE` is `default`, `strong` or `m=<M>,t=<T>,p=<P>`.
