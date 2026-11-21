// case-017: encrypt and decrypt a text with a password, from TypeScript.
// Run it with ./ts.sh, which creates tmp/password.txt first.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { BUILD, VERSION, decrypt, decryptToString, encrypt } from "../../typescript/dist/ssenc.node.ts";

console.log(`library version ${VERSION}, build "${BUILD}"`);

// A key is a plain object. The password is the demo password made by prepare.sh.
const password = readFileSync("tmp/password.txt", "utf8").trim();
const key = { type: "password", password } as const;

// encrypt: a string (or Uint8Array) goes in, an ASCII string comes out.
const plain = "user: admin\npassword: hunter2\n";
const encrypted: string = await encrypt(plain, key);
console.log("\nencrypted:\n" + encrypted);

// decryptToString: back to the original text.
const text: string = await decryptToString(encrypted, key);
console.log("decrypted as a string:\n" + text);
assert.equal(text, plain);

// decrypt: the original bytes, for data that is not text.
const bytes: Uint8Array = await decrypt(encrypted, key);
console.log("decrypted as bytes:", bytes.length, "bytes, first five:", Array.from(bytes.slice(0, 5)));

// Encrypting the same text again gives different output: every call makes a new random
// data key. (How to keep unchanged lines identical is shown in case-019.)
const again = await encrypt(plain, key);
assert.notEqual(again, encrypted);
console.log("\nencrypting the same text again gives a different result: ok");

// The password may also be given as bytes.
const keyFromBytes = { type: "password", password: new TextEncoder().encode(password) } as const;
assert.equal(await decryptToString(again, keyFromBytes), plain);
console.log("a password given as bytes opens it as well: ok");
