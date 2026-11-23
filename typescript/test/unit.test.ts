import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { argon2id } from "../src/03-argon2id.ts";
import { hkdf32, sivDecrypt, sivEncrypt, sivKey } from "../src/04-prim.ts";
import { b64urlDecode, b64urlEncode } from "../src/01-util.ts";
import * as nodeTs from "../dist/ssenc.node.ts";
// @ts-ignore transpiled builds have no type declarations next to them
import * as nodeJs from "../dist/ssenc.node.js";
import * as browserTs from "../dist/ssenc.browser.ts";
// @ts-ignore
import * as browserJs from "../dist/ssenc.browser.js";

const vectorsDir = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "tests", "vectors");
const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");
const unhex = (s: string): Uint8Array<ArrayBuffer> => new Uint8Array(Buffer.from(s, "hex"));
const prim = JSON.parse(readFileSync(join(vectorsDir, "primitives.json"), "utf8"));
const fileVectors: { name: string; key: { password?: string; ssh?: string } }[] =
  JSON.parse(readFileSync(join(vectorsDir, "vectors.json"), "utf8"));

type Lib = typeof nodeTs;
const builds: [string, Lib][] = [
  ["ssenc.node.ts", nodeTs], ["ssenc.node.js", nodeJs as Lib],
  ["ssenc.browser.ts", browserTs as unknown as Lib], ["ssenc.browser.js", browserJs as Lib],
];
const CHEAP = "m=64,t=1,p=1";
const autoVectors: { name: string; hex: string; mode: "lines" | "blob" }[] =
  JSON.parse(readFileSync(join(vectorsDir, "auto-mode.json"), "utf8"));

test("hkdf32 vectors", async () => {
  for (const v of prim.hkdf32) {
    assert.equal(hex(await hkdf32(unhex(v.ikm), v.salt === null ? null : unhex(v.salt), v.info)), v.out);
  }
});

test("siv vectors", async () => {
  for (const v of prim.siv) {
    const key = await sivKey(unhex(v.parent), v.purpose);
    assert.equal(hex(await sivEncrypt(key, unhex(v.ad), unhex(v.pt))), v.out);
    assert.equal(hex(await sivDecrypt(key, unhex(v.ad), unhex(v.out))), v.pt);
    const bad = unhex(v.out);
    bad[bad.length - 1] ^= 1;
    await assert.rejects(sivDecrypt(key, unhex(v.ad), bad), { kind: "AUTH" });
  }
});

test("argon2id vectors", () => {
  for (const v of prim.argon2id) {
    assert.equal(hex(argon2id(new TextEncoder().encode(v.password), unhex(v.salt), v.m, v.t, v.p, 32)), v.out);
  }
});

test("base64url", () => {
  for (let n = 0; n < 70; n++) {
    const b = Uint8Array.from({ length: n }, (_, i) => (i * 37 + n) & 255);
    const s = b64urlEncode(b);
    assert.match(s, /^[A-Za-z0-9_-]*$/);
    assert.deepEqual(b64urlDecode(s), b);
  }
  assert.equal(b64urlDecode("A"), null);
  assert.equal(b64urlDecode("ab=="), null);
  assert.equal(b64urlDecode("a+b/"), null);
});

for (const [name, lib] of builds) {
  test(name + ": password file vectors decrypt and re-encrypt identically", async () => {
    for (const v of fileVectors) {
      if (v.key.password === undefined) continue;
      const key = { type: "password" as const, password: v.key.password };
      const plain = new Uint8Array(readFileSync(join(vectorsDir, v.name, "plain.bin")));
      const enc = readFileSync(join(vectorsDir, v.name, "encrypted.txt"), "latin1");
      assert.deepEqual(new Uint8Array(await lib.decrypt(enc, key)), plain, v.name + " decrypt");
      assert.equal(await lib.encrypt(plain, key, { previous: enc }), enc, v.name + " re-encrypt");
    }
  });

  test(name + ": whitespace handling", async () => {
    const key = { type: "password" as const, password: "pw" };
    const plain = "a\n  b  \n\t\n\nc d\t\r\n   \r\ne";
    const on = await lib.encrypt(plain, key, { kdf: CHEAP });
    const lines = on.split("\n").slice(2);
    assert.match(lines[1], /^ {2}[A-Za-z0-9_-]+ {2}$/);
    assert.equal(lines[2], "\t");
    assert.equal(lines[3], "");
    assert.match(lines[4], /^[A-Za-z0-9_-]+\t\r$/);
    assert.equal(lines[5], "   \r");
    assert.equal(await lib.decryptToString(on, key), plain);
    const off = await lib.encrypt(plain, key, { kdf: CHEAP, preserveWhitespace: false });
    for (const l of off.split("\n").slice(2)) assert.match(l, /^[A-Za-z0-9_-]+\r?$/);
    assert.equal(await lib.decryptToString(off, key), plain);
    assert.equal(on.split("\n")[0], "#ssenc1 lines ws=1 pad=16");
    assert.equal(off.split("\n")[0], "#ssenc1 lines ws=0 pad=16");
  });

  test(name + ": equal lines give equal tokens, previous keeps unchanged lines", async () => {
    const key = { type: "password" as const, password: "pw" };
    const a = await lib.encrypt("x\ny\nx\nz\n", key, { kdf: CHEAP });
    const la = a.split("\n");
    assert.equal(la[2], la[4]);
    assert.notEqual(la[2], la[3]);
    const b = await lib.encrypt("x\nCHANGED\nx\nz\n", key, { previous: a });
    const lb = b.split("\n");
    assert.deepEqual(lb.map((l, i) => l === la[i]), [true, true, true, false, true, true, true]);
    const fresh = await lib.encrypt("x\ny\nx\nz\n", key, { kdf: CHEAP });
    assert.notEqual(fresh.split("\n")[2], la[2]);
  });

  test(name + ": mode auto picks lines for text and blob for anything else", async () => {
    const key = { type: "password" as const, password: "pw" };
    const auto = { mode: "auto", kdf: "m=8,t=1,p=1" } as const;
    assert.ok(autoVectors.filter((v) => v.mode === "lines").length >= 15 && autoVectors.filter((v) => v.mode === "blob").length >= 20);
    for (const v of autoVectors) {
      const input = unhex(v.hex);
      assert.equal(lib.detectMode(input), v.mode, v.name + " detectMode");
      const enc = await lib.encrypt(input, key, auto);
      assert.equal(lib.inspect(enc).mode, v.mode, v.name + " encrypt");
      assert.deepEqual(new Uint8Array(await lib.decrypt(enc, key)), input, v.name + " round trip");
    }
    // a string is examined as its UTF-8 bytes
    assert.equal(lib.detectMode("zażółć ∞ 😀\n"), "lines");
    assert.equal(lib.detectMode("a\0b"), "blob");

    // with previous the mode of the previous version is kept, whatever the new content is
    const text = "a\nb\n", binary = Uint8Array.from([97, 10, 255, 0, 10]);
    const v1 = await lib.encrypt(text, key, auto);
    const v2 = await lib.encrypt(binary, key, { mode: "auto", previous: v1 });
    assert.equal(lib.inspect(v2).mode, "lines");
    assert.deepEqual(new Uint8Array(await lib.decrypt(v2, key)), binary);
    const l1 = v1.split("\n"), l2 = v2.split("\n");
    assert.equal(l1.filter((l, i) => l !== l2[i]).length, 1);
    const b1 = await lib.encrypt(binary, key, auto);
    assert.equal(lib.inspect(b1).mode, "blob");
    assert.equal(lib.inspect(await lib.encrypt(text, key, { mode: "auto", previous: b1 })).mode, "blob");
    assert.equal(lib.inspect(await lib.encrypt(text, key, { mode: "lines", previous: b1 })).mode, "lines");

    // auto + seal: fine for text, refused when the input turns out to be binary
    assert.equal((lib.inspect(await lib.encrypt(text, key, { ...auto, seal: true })) as { seal: boolean }).seal, true);
    await assert.rejects(lib.encrypt(binary, key, { ...auto, seal: true }), { kind: "USAGE" });
    // @ts-expect-error not a mode
    await assert.rejects(lib.encrypt(text, key, { mode: "stream" }), { kind: "USAGE" });
    // @ts-expect-error not a mode, also not with previous
    await assert.rejects(lib.encrypt(text, key, { mode: "stream", previous: v1 }), { kind: "USAGE" });
  });

  test(name + ": blob, rekey, inspect, errors", async () => {
    const key = { type: "password" as const, password: "pw" };
    const data = Uint8Array.from({ length: 1000 }, (_, i) => (i * 7) & 255);
    const blob = await lib.encrypt(data, key, { kdf: CHEAP, mode: "blob", chunk: 100 });
    for (const l of blob.split("\n").slice(2)) assert.ok(l.length <= 76);
    assert.deepEqual(new Uint8Array(await lib.decrypt(blob, key)), data);
    assert.deepEqual(lib.inspect(blob), { format: "ssenc1", mode: "blob", chunk: 100, slots: [{ type: "pw", kdf: "argon2id", m: 64, t: 1, p: 1 }] });

    const key2 = { type: "password" as const, password: "other" };
    const rewrapped = await lib.rekey(blob, key, key2, { rotateDataKey: false, kdf: CHEAP });
    assert.deepEqual(rewrapped.split("\n").slice(2), blob.split("\n").slice(2));
    assert.deepEqual(new Uint8Array(await lib.decrypt(rewrapped, key2)), data);
    const rotated = await lib.rekey(blob, key, key2, { kdf: CHEAP });
    assert.notDeepEqual(rotated.split("\n").slice(2), blob.split("\n").slice(2));
    assert.deepEqual(new Uint8Array(await lib.decrypt(rotated, key2)), data);
    await assert.rejects(lib.decrypt(rotated, key), { kind: "AUTH" });

    await assert.rejects(lib.decrypt("hello", key), { kind: "MALFORMED" });
    await assert.rejects(lib.decrypt("#ssenc1 lines ws=1 pad=99999\n", key), { kind: "MALFORMED" });
    await assert.rejects(lib.encrypt("x", { type: "password", password: "" }), { kind: "USAGE" });
    await assert.rejects(lib.encrypt("x", []), { kind: "USAGE" });
    await assert.rejects(lib.encrypt("x", key, { mode: "blob", seal: true }), { kind: "USAGE" });
    const lines = (await lib.encrypt("secret\n", key, { kdf: CHEAP })).split("\n");
    lines[2] = (lines[2][0] === "A" ? "B" : "A") + lines[2].slice(1);
    await assert.rejects(lib.decrypt(lines.join("\n"), key), { kind: "AUTH" });
  });
}

test("browser build: ssh key without a signer is an ENV error; with a signer it works", async () => {
  const pub = readFileSync(join(vectorsDir, "..", "keys", "test_ed25519.pub"), "utf8");
  await assert.rejects(browserTs.encrypt("x", { type: "ssh", publicKey: pub }), { kind: "ENV" });
  await assert.rejects(browserTs.encrypt("x", { type: "ssh", fingerprint: "SHA256:x" }), { kind: "ENV" });
  // a fake but deterministic signer is enough to exercise the code path
  const str = (b: Uint8Array): Uint8Array => new Uint8Array([0, 0, 0, b.length, ...b]);
  const signer = async (_blob: Uint8Array, data: Uint8Array): Promise<Uint8Array> =>
    new Uint8Array([...str(new TextEncoder().encode("ssh-ed25519")), ...str(new Uint8Array(await crypto.subtle.digest("SHA-512", data as BufferSource)))]);
  const key = { type: "ssh" as const, publicKey: pub, signer };
  const enc = await browserTs.encrypt("hello\n", key);
  assert.equal(await browserTs.decryptToString(enc, key), "hello\n");
  const wrongAlg = async (): Promise<Uint8Array> => new Uint8Array([...str(new TextEncoder().encode("ssh-rsa")), ...str(new Uint8Array(64))]);
  await assert.rejects(browserTs.encrypt("x", { type: "ssh", publicKey: pub, signer: wrongAlg }), { kind: "ENV" });
});

test("kdf cache: same results, second derivation is skipped", async () => {
  const key = { type: "password" as const, password: "pw" };
  const enc = await nodeTs.encrypt("a\nb\n", key, { kdf: "m=32768,t=2,p=1" });
  const t0 = performance.now();
  await nodeTs.decrypt(enc, key);
  const cold = performance.now() - t0;
  nodeTs.setKdfCacheSize(4);
  try {
    assert.equal(await nodeTs.decryptToString(enc, key), "a\nb\n");
    const t1 = performance.now();
    assert.equal(await nodeTs.decryptToString(enc, key), "a\nb\n");
    assert.equal(await nodeTs.encrypt("a\nb\n", key, { previous: enc }), enc);
    const warm = (performance.now() - t1) / 2;
    assert.ok(warm < cold / 3, `cached ${warm.toFixed(1)} ms vs ${cold.toFixed(1)} ms`);
    await assert.rejects(nodeTs.decrypt(enc, { type: "password", password: "other" }), { kind: "AUTH" });
  } finally {
    nodeTs.setKdfCacheSize(0);
  }
});
