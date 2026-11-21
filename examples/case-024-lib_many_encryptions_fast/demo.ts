// case-024: many encryptions, fast.
// Each operation with a password runs Argon2id once, on purpose slow. That cost protects
// passwords a person could guess; a random 256-bit key needs none of it.
import assert from "node:assert/strict";
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { decrypt, decryptToString, encrypt, setKdfCacheSize } from "../../typescript/dist/ssenc.node.ts";

const names = readdirSync("tmp/plain").sort();
const seconds = (since: number): string => ((performance.now() - since) / 1000).toFixed(2) + " s";

// --- 1. the default cost, 3 files --------------------------------------------------------
const password = { type: "password", password: readFileSync("tmp/password.txt", "utf8").trim() } as const;
let start = performance.now();
for (const name of names.slice(0, 3)) await encrypt(readFileSync(`tmp/plain/${name}`), password);
console.log(`default cost:  3 files encrypted in ${seconds(start)}`);

// --- 2. a random key and the minimum cost, all 60 files ---------------------------------
const bulkKey = { type: "password", password: readFileSync("tmp/bulk.key", "utf8").trim() } as const;
const minimum = { kdf: "m=8,t=1,p=1" } as const;
start = performance.now();
for (const name of names) {
  writeFileSync(`tmp/fast/${name}.enc`, await encrypt(readFileSync(`tmp/plain/${name}`), bulkKey, minimum));
}
console.log(`minimum cost: ${names.length} files encrypted in ${seconds(start)}`);

// --- 3. decrypting needs no option: the cost is stored in every file --------------------
start = performance.now();
for (const name of names) {
  const plain = await decrypt(readFileSync(`tmp/fast/${name}.enc`), bulkKey);
  assert.deepEqual(Buffer.from(plain), readFileSync(`tmp/plain/${name}`));
}
console.log(`              ${names.length} files decrypted in ${seconds(start)}, all identical to the originals`);

// --- 4. updating all of them (previous) is just as fast ---------------------------------
start = performance.now();
for (const name of names) {
  const previous = readFileSync(`tmp/fast/${name}.enc`, "utf8");
  const edited = readFileSync(`tmp/plain/${name}`, "utf8") + "added: yes\n";
  const updated = await encrypt(edited, bulkKey, { previous });
  assert.equal(updated.split("\n").filter((line) => !previous.split("\n").includes(line)).length, 1);
}
console.log(`              ${names.length} files updated in ${seconds(start)}, one new line in each`);

// --- 5. the files are independent, so they can run concurrently -------------------------
// (One JavaScript thread does the work, so this helps little by itself; with real
//  parallelism, e.g. worker threads, it scales with the cores.)
start = performance.now();
await Promise.all(names.map((name) => encrypt(readFileSync(`tmp/plain/${name}`), bulkKey, minimum)));
console.log(`              ${names.length} files encrypted concurrently in ${seconds(start)}`);

// --- 6. a human password, same text again and again: the key cache ----------------------
// setKdfCacheSize(n) remembers the last n derived keys. It helps when the SAME password
// meets the SAME encrypted text again (each encrypted text has its own random salt), for
// example an editor that re-encrypts on every keystroke. Derived keys then stay in memory.
const v1 = await encrypt("draft 1\n", password);
setKdfCacheSize(8);
const timings: string[] = [];
let current = v1;
for (let i = 2; i <= 5; i++) {
  start = performance.now();
  current = await encrypt(`draft ${i}\n`, password, { previous: current });
  timings.push(seconds(start));
}
console.log(`\nkey cache, default cost: 4 updates of one text took ${timings.join(", ")}`);
assert.equal(await decryptToString(current, password), "draft 5\n");
setKdfCacheSize(0); // switches the cache off and forgets the keys

console.log("\nNEVER use the minimum cost with a password a person chose: guessing it would be cheap.");
