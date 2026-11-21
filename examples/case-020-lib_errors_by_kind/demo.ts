// case-020: every failure is an SsencError with a `kind`. This demo provokes each kind.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { SsencError, decrypt, decryptToString, encrypt, inspect } from "../../typescript/dist/ssenc.node.ts";

const key = { type: "password", password: readFileSync("tmp/password.txt", "utf8").trim() } as const;
const kdf = "m=19456,t=2,p=1"; // lower cost, only to keep the demo quick
const encrypted = await encrypt("the secret\n", key, { kdf });

// Runs something that must fail and reports the kind of failure.
async function failure(what: string, action: () => unknown): Promise<string> {
  try {
    await action();
  } catch (error) {
    if (error instanceof SsencError) {
      console.log(`${what}\n    -> ${error.kind}: ${error.message}`);
      return error.kind;
    }
    throw error; // not from the library: a bug
  }
  throw new Error(`${what}: did not fail`);
}

// AUTH: the key does not open the text, or the text was changed.
assert.equal(await failure("wrong password", () => decrypt(encrypted, { type: "password", password: "wrong" })), "AUTH");
const lines = encrypted.split("\n");
lines[2] = (lines[2][0] === "A" ? "B" : "A") + lines[2].slice(1);
assert.equal(await failure("one character of the encrypted text changed", () => decrypt(lines.join("\n"), key)), "AUTH");

// MALFORMED: the input is not encrypted text of this format.
assert.equal(await failure("decrypt of plain text", () => decrypt("just some text\n", key)), "MALFORMED");
assert.equal(await failure("inspect of plain text", () => inspect("just some text\n")), "MALFORMED");

// USAGE: the call itself is wrong.
assert.equal(await failure("empty password", () => encrypt("x", { type: "password", password: "" })), "USAGE");
assert.equal(await failure("pad out of range", () => encrypt("x", key, { pad: 100000 })), "USAGE");
assert.equal(await failure("no key at all", () => encrypt("x", [])), "USAGE");

// ENV: something outside the program is missing; here an ssh key without a reachable agent.
const sshKey = { type: "ssh", publicKey: readFileSync("tmp/demo_ed25519.pub", "utf8") } as const;
assert.equal(await failure("ssh key, but no ssh-agent", () => encrypt("x", sshKey)), "ENV");

// How it looks in real code: decide by kind, let everything else propagate.
async function open(text: string, password: string): Promise<string | null> {
  try {
    return await decryptToString(text, { type: "password", password });
  } catch (error) {
    if (error instanceof SsencError && error.kind === "AUTH") return null; // ask again
    throw error;
  }
}
assert.equal(await open(encrypted, "a guess"), null);
assert.equal(await open(encrypted, key.password), "the secret\n");
console.log("\nopen() returned null for a wrong password and the text for the right one: ok");
