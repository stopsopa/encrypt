// case-023: an ssh key WITHOUT ssh-agent. The library never needs the private key: it needs
// one signature. `signer` is the function that produces it, so the key can live anywhere:
// a file (as here), a vault, an HSM, a cloud key service, a browser extension.
import assert from "node:assert/strict";
import { createPrivateKey, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { decryptToString, encrypt, inspect } from "../../typescript/dist/ssenc.node.ts";
import type { SshSigner } from "../../typescript/dist/ssenc.node.ts";

// The private key made by prepare.sh. No agent is running: ts.sh did not start one.
assert.equal(process.env.SSH_AUTH_SOCK, undefined);
const privateKey = createPrivateKey(readFileSync("tmp/signer_key.pem"));
const publicKey = readFileSync("tmp/signer_key.pub", "utf8");

// SSH wire format of a byte string: 4-byte big-endian length, then the bytes.
function sshString(bytes: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + bytes.length);
  new DataView(out.buffer).setUint32(0, bytes.length);
  out.set(bytes, 4);
  return out;
}

// The signer gets the public key blob and the data to sign, and returns what an ssh-agent
// would return: string(algorithm) followed by string(signature).
let calls = 0;
const signer: SshSigner = async (publicKeyBlob, data) => {
  calls++;
  console.log(`    signer called: sign ${data.length} bytes for a key blob of ${publicKeyBlob.length} bytes`);
  const signature = sign(null, data, privateKey); // Ed25519: always the same signature for the same data
  return Buffer.concat([sshString(new TextEncoder().encode("ssh-ed25519")), sshString(signature)]);
};

// With a signer, publicKey is required (the fingerprint alone is not enough).
const key = { type: "ssh", publicKey, signer } as const;

const plain = "API_KEY=8f2c1d\nDB_PASSWORD=hunter2\n";
console.log("encrypt:");
const encrypted = await encrypt(plain, key);
console.log(encrypted);
console.log("the key slot looks exactly like one made through ssh-agent:", inspect(encrypted).slots);

console.log("\ndecrypt:");
assert.equal(await decryptToString(encrypted, key), plain);
console.log(`decrypted correctly; the signer was called ${calls} times (once per operation)`);

// A signer for another private key cannot open it.
const otherKey = createPrivateKey(readFileSync("tmp/other_key.pem"));
const wrongSigner: SshSigner = async (_blob, data) =>
  Buffer.concat([sshString(new TextEncoder().encode("ssh-ed25519")), sshString(sign(null, data, otherKey))]);
await assert.rejects(decryptToString(encrypted, { type: "ssh", publicKey, signer: wrongSigner }), { kind: "AUTH" });
console.log("a signer that uses a different private key is rejected (AUTH): ok");

// A signer that fails surfaces as an ENV error.
const broken: SshSigner = async () => {
  throw new Error("the vault is sealed");
};
await assert.rejects(decryptToString(encrypted, { type: "ssh", publicKey, signer: broken }), { kind: "ENV" });
console.log("a signer that throws is reported as ENV: ok");

// The browser build has no ssh-agent at all: there a signer is the only way to use an
// ssh key. It is the same code with import ... from "./ssenc.browser.js".
