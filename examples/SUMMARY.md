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

## case-001-cli_text_with_password

Encrypt a text from standard input with a password and decrypt it.

```sh
export SSENC_PASSWORD="$(openssl rand -base64 24)"

echo "my first secret" | $S encrypt > secret.enc
$S decrypt < secret.enc                      # my first secret
```

## case-002-cli_file_with_password

Encrypt and decrypt a file; the password is read from a file.

```sh
openssl rand -base64 24 > password.txt

$S encrypt --password-file password.txt -i  xx.ts -o xx.ts.enc
$S decrypt --password-file password.txt -i xx.ts.enc -o xx.ts.decoded
diff xx.ts xx.ts.decoded 
$S decrypt --password-file password.txt -i xx.ts.enc      # to standard output

$S encrypt --password-file password.txt -i xx.ts.decoded -o xx.ts.decoded   # in place: same file in and out
$S decrypt --password-file password.txt -i xx.ts.decoded -o xx.ts.decoded 
diff xx.ts xx.ts.decoded 
```

## case-003-cli_binary_file_blob_mode

Any bytes (an image, an archive) become ASCII text and come back identical.

```sh
$S encrypt --mode blob --password-file password.txt -i s/i.jpg -o s/i.jpg.txt
$S decrypt --password-file password.txt -i s/i.jpg.txt -o s/i.jpg   # no --mode: it is in the file
ls -la s/i*

$S encrypt --mode blob --chunk 16384 --password-file password.txt -i photo.bin -o photo.bin.enc
```

## case-004-cli_inspect_without_key

See how a file was encrypted, without having the key.

```sh
$S inspect -i notes.txt.enc
# {"format":"ssenc1","mode":"lines","ws":true,"pad":16,"seal":false,"slots":[{"type":"pw","kdf":"argon2id","m":65536,"t":3,"p":4}]}

$S inspect -i notes.txt     # not an encrypted file: exit code 3
$S --version
```

## case-005-cli_update_changes_only_edited_lines

After an edit of the plain file, only the edited line changes in the encrypted file.

```sh
$S encrypt --password-file password.txt -i config.yml -o config.yml.enc   # first time
# ... edit one line of config.yml ...
$S encrypt --password-file password.txt -i config.yml -o config.yml.enc   # existing output is reused
git diff config.yml.enc                                                      # one line differs

$S encrypt --password-file password.txt --previous old.enc -i config.yml -o other.enc   # reuse another file
$S encrypt --password-file password.txt --fresh -i config.yml -o config.yml.enc         # start over: every line changes
```

## case-006-cli_whitespace_and_padding

What stays visible in an encrypted line: indentation and rough length.

```sh
$S encrypt --password-file password.txt -i app.yml -o app.enc                    # indentation stays visible
$S encrypt --no-preserve-ws --password-file password.txt -i app.yml -o app.enc   # indentation is encrypted too
$S encrypt --pad 0 --password-file password.txt -i app.yml -o app.enc            # no padding: exact line lengths show
$S encrypt --pad 128 --password-file password.txt -i app.yml -o app.enc          # all short lines look the same length
```

## case-007-cli_seal_detects_removed_lines

A changed line is always detected; a removed or moved line only with `--seal`.

```sh
$S encrypt --password-file password.txt -i rules.txt -o rules.enc
sed "5d" rules.enc | $S decrypt --password-file password.txt      # works: one line is silently missing

$S encrypt --seal --password-file password.txt -i rules.txt -o sealed.enc
sed "6d" sealed.enc | $S decrypt --password-file password.txt     # exit code 2
```

## case-008-cli_password_cost_kdf

How expensive it is to turn the password into a key (and so to guess it).

```sh
$S encrypt --password-file password.txt -i secret.txt -o secret.enc                        # default: 64 MiB, 3 passes
$S encrypt --kdf strong --password-file password.txt -i secret.txt -o secret.enc           # 1 GiB, 4 passes
$S encrypt --kdf m=19456,t=2,p=1 --password-file password.txt -i secret.txt -o secret.enc  # your own numbers

$S decrypt --password-file password.txt -i secret.enc     # no option: the cost is stored in the file
```

## case-009-cli_errors_and_exit_codes

Every kind of failure has its own exit code.

```sh
$S decrypt --password-file password.txt -i secret.enc      # 0
SSENC_PASSWORD="wrong" $S decrypt -i secret.enc            # 2  AUTH: wrong key, or the file was modified
echo "just some text" | $S decrypt                         # 3  MALFORMED: not an ssenc file
$S decrypt --no-such-option -i secret.enc                  # 1  USAGE: bad arguments, empty or missing password
$S encrypt --ssh-key key.pub -i secret.txt                 # 4  ENV: no ssh-agent, or the key is not in it

$S decrypt -i secret.enc -o secret.txt || echo "failed with $?"
```

## case-010-cli_rekey_change_password

Change the password of an encrypted file.

```sh
$S rekey --password-file old.txt --new-password-file new.txt -i config.yml.enc -o config.yml.enc

# the same with environment variables
SSENC_PASSWORD="old" SSENC_NEW_PASSWORD="new" $S rekey -i config.yml.enc -o config.yml.enc

# only the key line at the top changes, the rest of the file stays byte-identical
$S rekey --rewrap-only --password-file old.txt --new-password-file new.txt -i config.yml.enc -o config.yml.enc
```

## case-011-cli_ssh_key_from_ssh_agent

An ssh key instead of a password. The private key stays in `ssh-agent`.

```sh
ssh-keygen -t ed25519 -f demo_key        # or -t rsa
ssh-add demo_key

$S encrypt --ssh-key demo_key.pub -i secrets.env -o secrets.env.enc
$S decrypt --ssh-key demo_key.pub -i secrets.env.enc

$S decrypt --ssh-key "SHA256:..." -i secrets.env.enc      # the key named by fingerprint (ssh-add -l)
```

## case-012-cli_several_keys_ssh_and_backup_password

One file that several people can open, plus a backup password.

```sh
$S encrypt --ssh-key alice.pub --ssh-key bob.pub --password-file backup-password.txt -i secrets.env -o secrets.env.enc

$S decrypt --ssh-key alice.pub -i secrets.env.enc                     # any one of the three opens it
$S decrypt --ssh-key bob.pub -i secrets.env.enc
$S decrypt --password-file backup-password.txt -i secrets.env.enc

# an update made with one key keeps all three keys
$S encrypt --ssh-key bob.pub -i secrets.env -o secrets.env.enc
```

## case-013-cli_rekey_between_password_and_ssh_key

Move a file from a password to an ssh key and back; add and remove keys.

```sh
# password -> ssh key
$S rekey --password-file password.txt --new-ssh-key me.pub -i secrets.env.enc -o secrets.env.enc

# add keys: list every key the file should have from now on
$S rekey --ssh-key me.pub --new-ssh-key me.pub --new-ssh-key other.pub --new-password-file backup.txt -i secrets.env.enc -o secrets.env.enc

# remove a key: leave it out
$S rekey --ssh-key me.pub --new-ssh-key me.pub -i secrets.env.enc -o secrets.env.enc

# ssh key -> password
$S rekey --ssh-key me.pub --new-password-file password.txt -i secrets.env.enc -o secrets.env.enc
```

## case-014-cli_many_files_fast_with_random_key

Many files quickly: a random key file instead of a human password, and the minimum password cost.

```sh
openssl rand -base64 32 > bulk.key       # 256 random bits: nothing to guess, so the cost can be minimal

for f in plain/*.txt; do
  $S encrypt --kdf m=8,t=1,p=1 --password-file bulk.key -i "$f" -o "encrypted/$(basename "$f").enc"
done

# in parallel, 4 at a time
ls plain | xargs -P 4 -I {} $S encrypt --kdf m=8,t=1,p=1 --password-file bulk.key -i plain/{} -o encrypted/{}.enc
```

Never use `--kdf m=8,t=1,p=1` with a password a person chose.

## case-015-cli_other_implementations_read_the_same_files

A file made by one implementation is read, updated and rekeyed by the other two.

```sh
rust/target/release/ssenc encrypt --password-file password.txt -i config.yml -o config.yml.enc
typescript/bin/ssenc      decrypt --password-file password.txt -i config.yml.enc
bash/bin/ssenc            decrypt --password-file password.txt -i config.yml.enc

# ... edit one line of config.yml ...
typescript/bin/ssenc      encrypt --password-file password.txt -i config.yml -o config.yml.enc   # still a one-line diff
bash/bin/ssenc            rekey --password-file password.txt --new-ssh-key me.pub -i config.yml.enc -o config.yml.enc
rust/target/release/ssenc decrypt --ssh-key me.pub -i config.yml.enc
```

## case-016-cli_git_diff_shows_the_edited_line

Keep the encrypted file in git; let git show diffs of the plain text.

```sh
echo "settings.yml" > .gitignore                 # the plain file is never committed
$S encrypt --password-file ~/password.txt -i settings.yml -o settings.yml.enc
git add .gitignore settings.yml.enc && git commit -m "settings, encrypted"

# ... edit one line of settings.yml, encrypt again ...
git diff                                         # one encrypted line differs

# show the plain text in diffs instead
echo "*.enc diff=ssenc" > .gitattributes
git config diff.ssenc.textconv "$S decrypt --password-file $HOME/password.txt -i"
git diff
```

## case-017-lib_text_with_password

The library: encrypt and decrypt a text.

```ts
import { encrypt, decrypt, decryptToString } from "./ssenc.node.ts";   // also: ssenc.node.js, ssenc.browser.js

const key = { type: "password", password: "..." } as const;
const encrypted: string = await encrypt("user: admin\npassword: hunter2\n", key);
const bytes: Uint8Array = await decrypt(encrypted, key);
const text: string = await decryptToString(encrypted, key);
```

```rust
use ssenc::{decrypt, encrypt, EncryptOptions, Key};

let key = Key::password("...");
let encrypted: String = encrypt(b"user: admin\npassword: hunter2\n", &[key.clone()], &EncryptOptions::default())?;
let bytes: Vec<u8> = decrypt(encrypted.as_bytes(), &key)?;
```

```sh
source bash/ssenc.sh
export SSENC_PASSWORD="..."

encrypted="$(printf "user: admin\npassword: hunter2\n" | ssenc_encrypt)"
echo "$encrypted" | ssenc_decrypt
```

## case-018-lib_files_text_and_binary

Text file line by line, binary file as a blob, `inspect`.

```ts
const config = await encrypt(readFileSync("config.yml"), key);                    // lines mode
const photo = await encrypt(readFileSync("photo.bin"), key, { mode: "blob" });    // any bytes
const small = await encrypt(readFileSync("photo.bin"), key, { mode: "blob", chunk: 4096 });

inspect(photo);                          // { format, mode, chunk, slots, ... } without a key
const back = await decrypt(photo, key);  // Uint8Array
```

```rust
let blob = EncryptOptions { mode: Some(Mode::Blob), ..Default::default() };
let photo = encrypt(&fs::read("photo.bin")?, &[key.clone()], &blob)?;

println!("{}", inspect(photo.as_bytes())?.to_json());
let back = decrypt(photo.as_bytes(), &key)?;
```

```sh
ssenc_encrypt --mode blob --password-file password.txt -i photo.bin -o photo.bin.enc
ssenc_inspect -i photo.bin.enc
ssenc_decrypt --password-file password.txt -i photo.bin.enc -o photo.bin
```

## case-019-lib_options_and_stable_updates

Every option of `encrypt`; updates that change only the edited lines.

```ts
await encrypt(plain, key, { kdf: { m: 19456, t: 2, p: 1 } });   // or "default", "strong", "m=19456,t=2,p=1"
await encrypt(plain, key, { preserveWhitespace: false });
await encrypt(plain, key, { pad: 64 });
await encrypt(plain, key, { seal: true });

const v1 = await encrypt(plain, key);
const v2 = await encrypt(edited, key, { previous: v1 });        // only the edited lines differ from v1
```

```rust
let options = EncryptOptions {
    kdf: Some("m=19456,t=2,p=1".into()),
    preserve_whitespace: Some(false),
    pad: Some(64),
    seal: Some(true),
    ..Default::default()
};
let v1 = encrypt(plain, &[key.clone()], &options)?;

let update = EncryptOptions { previous: Some(v1.clone().into_bytes()), ..Default::default() };
let v2 = encrypt(edited, &[key.clone()], &update)?;             // only the edited lines differ from v1
```

```sh
ssenc_encrypt --kdf m=19456,t=2,p=1 --no-preserve-ws --pad 64 --seal -i app.yml -o v1.enc
ssenc_encrypt --previous v1.enc -i edited.yml -o v2.enc
```

## case-020-lib_errors_by_kind

Every error has a kind: `USAGE`, `AUTH`, `MALFORMED`, `ENV`.

```ts
import { SsencError, decryptToString } from "./ssenc.node.ts";

try {
  return await decryptToString(encrypted, { type: "password", password: guess });
} catch (error) {
  if (error instanceof SsencError && error.kind === "AUTH") return null;   // wrong password: ask again
  throw error;                                                             // MALFORMED, USAGE, ENV
}
```

```rust
match decrypt(text.as_bytes(), &Key::password(guess)) {
    Ok(plain) => Ok(Some(plain)),
    Err(error) if error.kind == ErrorKind::Auth => Ok(None),   // wrong password: ask again
    Err(error) => Err(error),                                  // Malformed, Usage, Env
}
```

```sh
ssenc_decrypt -i secret.enc
case $? in
  0) ;;
  2) echo "wrong password, or the file was modified" ;;
  3) echo "not an encrypted file" ;;
  *) echo "usage (1) or environment (4) problem" ;;
esac
```

## case-021-lib_rekey_replace_keys

Replace the keys of an encrypted text.

```ts
const rotated = await rekey(encrypted, oldKey, newKey);                              // everything re-encrypted
const rewrapped = await rekey(encrypted, oldKey, newKey, { rotateDataKey: false });  // only the key line changes
const two = await rekey(encrypted, oldKey, [newKey, thirdKey]);                      // several new keys
```

```rust
let rotated = rekey(encrypted.as_bytes(), &old_key, &[new_key.clone()], &RekeyOptions::default())?;
let rewrap = RekeyOptions { rotate_data_key: false, kdf: None };
let rewrapped = rekey(encrypted.as_bytes(), &old_key, &[new_key.clone()], &rewrap)?;
```

```sh
ssenc_rekey --password-file old.txt --new-password-file new.txt -i original.enc -o rotated.enc
ssenc_rekey --rewrap-only --password-file old.txt --new-password-file new.txt -i original.enc -o rewrapped.enc
```

## case-022-lib_ssh_agent_keys

ssh keys from `ssh-agent`: by public key, by fingerprint, together with a password.

```ts
const sshKey = { type: "ssh", publicKey: readFileSync("demo_key.pub", "utf8") } as const;
const encrypted = await encrypt(plain, sshKey);
await decryptToString(encrypted, sshKey);
await decryptToString(encrypted, { type: "ssh", fingerprint: "SHA256:..." });
await decryptToString(encrypted, { type: "ssh", publicKey, agentSocket: "/path/agent.sock" });

const shared = await encrypt(plain, [sshKey, otherSshKey, backupPassword]);   // any one opens it
```

```rust
let ssh_key = Key::ssh_public_key(fs::read_to_string("demo_key.pub")?);
let encrypted = encrypt(plain, &[ssh_key.clone()], &EncryptOptions::default())?;
decrypt(encrypted.as_bytes(), &ssh_key)?;
decrypt(encrypted.as_bytes(), &Key::ssh_fingerprint("SHA256:..."))?;

let shared = encrypt(plain, &[ssh_key, other_ssh_key, backup_password], &EncryptOptions::default())?;
```

```sh
ssenc_encrypt --ssh-key demo_key.pub -i plain.env -o secret.enc
ssenc_decrypt --ssh-key demo_key.pub -i secret.enc
SSH_AUTH_SOCK=/path/agent.sock ssenc_decrypt --ssh-key "SHA256:..." -i secret.enc
```

## case-023-lib_ssh_key_with_own_signer

An ssh key that is not in an agent (a file, a vault, a hardware module): you supply the function that signs.

```ts
import { createPrivateKey, sign } from "node:crypto";
import type { SshSigner } from "./ssenc.node.ts";

const privateKey = createPrivateKey(readFileSync("signer_key.pem"));
const sshString = (b: Uint8Array) => { const n = Buffer.alloc(4); n.writeUInt32BE(b.length); return Buffer.concat([n, b]); };

// returns what an ssh-agent would return: string(algorithm) followed by string(signature)
const signer: SshSigner = async (publicKeyBlob, data) =>
  Buffer.concat([sshString(Buffer.from("ssh-ed25519")), sshString(sign(null, data, privateKey))]);

const key = { type: "ssh", publicKey, signer } as const;      // publicKey is required with a signer
const encrypted = await encrypt(plain, key);
```

```rust
let signer: SshSigner = Arc::new(|_public_key_blob: &[u8], data: &[u8]| {
    let signature = my_ed25519_sign(data)?;                   // 64 bytes, from wherever the key lives
    Ok([ssh_string(b"ssh-ed25519"), ssh_string(&signature)].concat())
});
let key = Key::Ssh { public_key: Some(public_key), fingerprint: None, agent_socket: None, signer: Some(signer) };
let encrypted = encrypt(plain, &[key.clone()], &EncryptOptions::default())?;
```

```sh
# Bash has no signer function; it can only choose which agent is asked
SSH_AUTH_SOCK=/path/to/agent.sock ssenc_encrypt --ssh-key demo_key.pub -i plain.env -o secret.enc
```

## case-024-lib_many_encryptions_fast

Many encryptions from one program: random key, minimum password cost, all cores, key cache.

```ts
const bulkKey = { type: "password", password: readFileSync("bulk.key", "utf8").trim() } as const;  // openssl rand -base64 32
const minimum = { kdf: "m=8,t=1,p=1" } as const;      // only for a random key, never for a human password

await Promise.all(names.map((name) => encrypt(readFileSync(name), bulkKey, minimum)));

setKdfCacheSize(8);   // same password + same file again and again: the derived key is remembered
setKdfCacheSize(0);   // off, keys forgotten
```

```rust
let bulk_key = Key::password(fs::read_to_string("bulk.key")?.trim());
let minimum = EncryptOptions { kdf: Some("m=8,t=1,p=1".into()), ..Default::default() };

std::thread::scope(|scope| {
    for name in &names {
        scope.spawn(|| encrypt(&fs::read(name).unwrap(), &[bulk_key.clone()], &minimum));
    }
});
```

```sh
for f in plain/*.txt; do
  ssenc_encrypt --kdf m=8,t=1,p=1 --password-file bulk.key -i "$f" -o "encrypted/$(basename "$f").enc" &
done
wait
```
