// case-019: every option of encrypt, and how to update an encrypted text so that only the
// edited lines change.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { SsencError, decryptToString, encrypt, inspect } from "../../typescript/dist/ssenc.node.ts";

const key = { type: "password", password: readFileSync("tmp/password.txt", "utf8").trim() } as const;
const plain = readFileSync("tmp/app.yml", "utf8");
const body = (encrypted: string): string => encrypted.split("\n").filter((line) => !line.startsWith("#")).join("\n");

// --- kdf: the cost of turning the password into a key ----------------------------------
// "default" (64 MiB, 3 passes), "strong" (1 GiB, 4 passes), a string "m=..,t=..,p=.." or an
// object. The lower cost below is used for the rest of this demo only to keep it quick.
const kdf = { m: 19456, t: 2, p: 1 }; // m is in KiB
const v1 = await encrypt(plain, key, { kdf });
console.log("default options (indentation readable, lines padded to 16 bytes):\n" + v1);
console.log(inspect(v1));

// --- preserveWhitespace: false -> indentation and empty lines are encrypted too ---------
const noWs = await encrypt(plain, key, { kdf: "m=19456,t=2,p=1", preserveWhitespace: false });
console.log("\npreserveWhitespace: false\n" + body(noWs));

// --- pad: 0 -> no padding; a bigger value hides line lengths better ---------------------
const pad0 = await encrypt(plain, key, { kdf, pad: 0 });
const pad64 = await encrypt(plain, key, { kdf, pad: 64 });
console.log("pad: 0\n" + body(pad0));
console.log("pad: 64\n" + body(pad64));

// --- previous: update an encrypted text; unchanged lines stay identical -----------------
const edited = plain.replace("port: 8080", "port: 9090");
const v2 = await encrypt(edited, key, { previous: v1 });
const linesV1 = v1.split("\n");
const linesV2 = v2.split("\n");
const changed = linesV2.filter((line, i) => line !== linesV1[i]);
console.log(`previous: ${changed.length} of ${linesV2.length - 1} lines changed after editing one line`);
assert.equal(changed.length, 1);
assert.equal(await decryptToString(v2, key), edited);

// Without `previous` a new data key is made and every line changes.
const unrelated = await encrypt(edited, key, { kdf });
assert.equal(unrelated.split("\n").filter((line, i) => line !== linesV1[i] && line.trim() !== "").length, 6);
console.log("without previous: every line changed");

// The key must open `previous`; otherwise nothing is produced.
await assert.rejects(encrypt(edited, { type: "password", password: "another password" }, { previous: v1 }), { kind: "AUTH" });
console.log("previous with a key that does not open it: rejected (AUTH)");

// --- seal: a checksum over the whole text; removed or reordered lines are detected ------
const sealed = await encrypt(plain, key, { kdf, seal: true });
console.log("\nseal: true\n" + sealed);
const withoutLastLine = sealed.split("\n").slice(0, -2).join("\n") + "\n";
try {
  await decryptToString(withoutLastLine, key);
  assert.fail("a sealed text with a removed line must not decrypt");
} catch (error) {
  assert.ok(error instanceof SsencError && error.kind === "AUTH");
  console.log("sealed text with one line removed: rejected (AUTH)");
}
// Unsealed, the same removal goes unnoticed: the remaining lines decrypt.
const shortened = await decryptToString(v1.split("\n").slice(0, -2).join("\n") + "\n", key);
console.log("unsealed text with one line removed still decrypts, to", shortened.split("\n").length - 1, "lines instead of 6");

// --- options not given are taken from `previous` -----------------------------------------
const sealedV2 = await encrypt(edited, key, { previous: sealed });
const info = inspect(sealedV2);
assert.ok(info.mode === "lines" && info.seal === true);
console.log("an update of a sealed text is sealed again:", info);

// --- all decrypt to what was encrypted, with no options ---------------------------------
for (const encrypted of [v1, noWs, pad0, pad64, sealed]) assert.equal(await decryptToString(encrypted, key), plain);
console.log("\nall variants decrypt to the original without any option: ok");
