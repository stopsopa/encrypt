// case-018: encrypt a text file line by line and a binary file as a blob; read the
// encrypted files back, look at them without a key, decrypt them.
import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { decrypt, detectMode, encrypt, inspect } from "../../typescript/dist/ssenc.node.ts";

const key = { type: "password", password: readFileSync("tmp/password.txt", "utf8").trim() } as const;

// --- a text file: lines mode (the default) --------------------------------------------
const config = readFileSync("tmp/config.yml"); // a Buffer is a Uint8Array
const configEncrypted = await encrypt(config, key);
writeFileSync("tmp/config.yml.enc", configEncrypted); // the result is text: write it as it is
console.log("tmp/config.yml.enc:\n" + configEncrypted);

// --- a binary file: blob mode -----------------------------------------------------------
const photo = readFileSync("tmp/photo.bin");
const photoEncrypted = await encrypt(photo, key, { mode: "blob" });
writeFileSync("tmp/photo.bin.enc", photoEncrypted);
console.log(`tmp/photo.bin.enc: ${photo.length} bytes became ${photoEncrypted.length} characters of ASCII, first lines:`);
console.log(photoEncrypted.split("\n").slice(0, 4).join("\n") + "\n");

// --- inspect: no key needed, not async -------------------------------------------------
console.log("inspect config:", inspect(readFileSync("tmp/config.yml.enc")));
console.log("inspect photo: ", inspect(readFileSync("tmp/photo.bin.enc")));

// --- decrypt: the input may be a string or bytes; mode and settings are read from it ---
const configBack = await decrypt(readFileSync("tmp/config.yml.enc"), key);
const photoBack = await decrypt(readFileSync("tmp/photo.bin.enc", "utf8"), key);
writeFileSync("tmp/photo.decrypted.bin", photoBack);
assert.deepEqual(Buffer.from(configBack), config);
assert.deepEqual(Buffer.from(photoBack), photo);
console.log("\nboth files decrypt to exactly the original bytes: ok");

// --- blob mode with a smaller chunk size ------------------------------------------------
const small = await encrypt(photo, key, { mode: "blob", chunk: 4096 });
console.log("chunk 4096:", inspect(small));
assert.deepEqual(Buffer.from(await decrypt(small, key)), photo);
console.log("the file with small chunks decrypts to the original as well: ok");

// --- mode "auto": lines for text (no NUL byte, valid UTF-8), blob for anything else ------
console.log("\ndetectMode:", { config: detectMode(config), photo: detectMode(photo) });
const configAuto = await encrypt(config, key, { mode: "auto" });
const photoAuto = await encrypt(photo, key, { mode: "auto" });
assert.equal(inspect(configAuto).mode, "lines");
assert.equal(inspect(photoAuto).mode, "blob");
console.log("mode auto: the text file was encrypted line by line, the binary file as a blob: ok");

// With previous, auto keeps the mode of the previous version whatever the new content is.
const stillLines = await encrypt(photo.subarray(0, 100), key, { mode: "auto", previous: configAuto });
assert.equal(inspect(stillLines).mode, "lines");
console.log("mode auto with previous: the mode of the previous version is kept: ok");
