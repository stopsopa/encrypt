// case-021: rekey replaces the keys of an encrypted text.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { decryptToString, encrypt, inspect, rekey } from "../../typescript/dist/ssenc.node.ts";

const oldKey = { type: "password", password: readFileSync("tmp/old-password.txt", "utf8").trim() } as const;
const newKey = { type: "password", password: readFileSync("tmp/new-password.txt", "utf8").trim() } as const;
const kdf = "m=19456,t=2,p=1"; // lower cost, only to keep the demo quick
const plain = "host: db.internal\nuser: admin\npassword: hunter2\n";
const dataLines = (text: string): string[] => text.split("\n").filter((line) => line !== "" && !line.startsWith("#"));

const original = await encrypt(plain, oldKey, { kdf });
console.log("encrypted with the old password:\n" + original);

// --- rekey(text, oldKey, newKey): everything is encrypted again under a new data key ----
const rotated = await rekey(original, oldKey, newKey, { kdf });
console.log("after rekey:\n" + rotated);
await assert.rejects(decryptToString(rotated, oldKey), { kind: "AUTH" });
assert.equal(await decryptToString(rotated, newKey), plain);
assert.equal(dataLines(rotated).filter((line) => dataLines(original).includes(line)).length, 0);
console.log("the old password is rejected, the new one opens it, and every line changed: ok\n");

// --- rotateDataKey: false -> only the key line is replaced, the data lines stay ---------
// Cheap and a small diff, but weaker: whoever knows the old password and kept an old copy
// can still read later versions.
const rewrapped = await rekey(original, oldKey, newKey, { kdf, rotateDataKey: false });
assert.deepEqual(dataLines(rewrapped), dataLines(original));
await assert.rejects(decryptToString(rewrapped, oldKey), { kind: "AUTH" });
assert.equal(await decryptToString(rewrapped, newKey), plain);
console.log("rotateDataKey: false -> data lines identical, only the key line differs: ok");

// --- several new keys: any one of them opens the result ---------------------------------
const thirdKey = { type: "password", password: "a third password" } as const;
const two = await rekey(original, oldKey, [newKey, thirdKey], { kdf });
console.log("\ntwo new keys:", inspect(two).slots);
assert.equal(await decryptToString(two, newKey), plain);
assert.equal(await decryptToString(two, thirdKey), plain);

// --- kdf: the cost of the new password keys (the default cost when left out) ------------
const defaultCost = await rekey(two, thirdKey, newKey);
console.log("rekey without kdf uses the default cost:", inspect(defaultCost).slots);

// --- the mode and its settings are kept --------------------------------------------------
const blob = await encrypt(new Uint8Array([0, 1, 2, 255]), oldKey, { kdf, mode: "blob", chunk: 1024 });
console.log("\na blob stays a blob with its chunk size:", inspect(await rekey(blob, oldKey, newKey, { kdf })));
