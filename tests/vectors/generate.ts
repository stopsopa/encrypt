// Regenerates the known-answer vectors with the TypeScript implementation.
// Only needed when the format changes; the committed vectors are the contract.
//   eval "$(tests/lib/agent.sh start)"; node tests/vectors/generate.ts; tests/lib/agent.sh stop
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { argon2id } from "../../typescript/src/03-argon2id.ts";
import { hkdf32, sivEncrypt, sivKey } from "../../typescript/src/04-prim.ts";
import { encrypt } from "../../typescript/dist/ssenc.node.ts";
import type { Key, EncryptOptions } from "../../typescript/dist/ssenc.node.ts";

const here = dirname(fileURLToPath(import.meta.url));
const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");
const unhex = (s: string): Uint8Array<ArrayBuffer> => new Uint8Array(Buffer.from(s, "hex"));
const seq = (n: number, start = 0): Uint8Array<ArrayBuffer> => Uint8Array.from({ length: n }, (_, i) => (start + i) & 255);

// ---- primitives -------------------------------------------------------------------------
const prim: Record<string, unknown[]> = { hkdf32: [], siv: [], argon2id: [] };
for (const [ikm, salt, info] of [
  [hex(seq(32)), null, "ssenc1/line-mac"],
  [hex(seq(32)), null, "ssenc1/wrap-enc"],
  [hex(seq(83, 7)), hex(seq(32, 100)), "ssenc1/ssh-kek"],
] as const) {
  prim.hkdf32.push({ ikm, salt, info, out: hex(await hkdf32(unhex(ikm), salt === null ? null : unhex(salt), info)) });
}
// SIV vectors are expressed through a parent key and purpose, exactly as the format uses it:
// Kmac = HKDF32(parent, none, "ssenc1/<purpose>-mac"), Kenc = HKDF32(parent, none, "ssenc1/<purpose>-enc")
for (const [parent, purpose, ad, pt] of [
  [hex(seq(32)), "line", "", ""],
  [hex(seq(32)), "line", "", hex(new TextEncoder().encode("hello world"))],
  [hex(seq(32, 50)), "blob", "000000000000000001", hex(seq(100))],
  [hex(seq(32, 50)), "wrap", hex(new TextEncoder().encode("ssenc1/slot")), hex(seq(32, 200))],
  [hex(seq(32, 9)), "blob", "000000000000000300", hex(seq(4096, 3))],
] as const) {
  const key = await sivKey(unhex(parent), purpose);
  prim.siv.push({
    parent, purpose, ad, pt,
    kmac: hex(await hkdf32(unhex(parent), null, "ssenc1/" + purpose + "-mac")),
    kenc: hex(await hkdf32(unhex(parent), null, "ssenc1/" + purpose + "-enc")),
    out: hex(await sivEncrypt(key, unhex(ad), unhex(pt))),
  });
}
for (const [password, salt, m, t, p] of [
  ["hunter2", "000102030405060708090a0b0c0d0e0f", 8192, 1, 1],
  ["correct horse battery staple", "ffeeddccbbaa99887766554433221100", 64, 2, 4],
  ["pässwörd ✓", "00112233445566778899aabbccddeeff", 1024, 3, 2],
  ["hunter2", "000102030405060708090a0b0c0d0e0f", 65536, 3, 4],
] as const) {
  prim.argon2id.push({ password, salt, m, t, p, out: hex(argon2id(new TextEncoder().encode(password), unhex(salt), m, t, p, 32)) });
}
writeFileSync(join(here, "primitives.json"), JSON.stringify(prim, null, 2) + "\n");

// ---- files ------------------------------------------------------------------------------
const pub = (name: string): string => readFileSync(join(here, "..", "keys", name + ".pub"), "utf8");
const cheap = "m=8192,t=1,p=1";
type V = { name: string; plain: Uint8Array | string; password?: string; ssh?: string[]; openWith: Record<string, string>; options: EncryptOptions };
const text = "# config\nserver:\n    host: db.internal  \n\tport: 5432\r\n\n   \n  password: \"s3cr3t ✓\"\t\nserver:\nlast line without newline";
const vectors: V[] = [
  { name: "lines-default", plain: text, password: "hunter2", openWith: { password: "hunter2" }, options: { kdf: cheap } },
  { name: "lines-ws0-pad0-seal", plain: text, password: "hunter2", openWith: { password: "hunter2" }, options: { kdf: cheap, preserveWhitespace: false, pad: 0, seal: true } },
  { name: "lines-pad1-multislot", plain: text + "\n", password: "pässwörd ✓", ssh: ["test_ed25519", "test_rsa"], openWith: { password: "pässwörd ✓" }, options: { kdf: "m=64,t=2,p=4", pad: 1 } },
  { name: "lines-empty", plain: "", password: "x", openWith: { password: "x" }, options: { kdf: cheap } },
  { name: "lines-binary", plain: seq(600), password: "x", openWith: { password: "x" }, options: { kdf: cheap, pad: 7 } },
  { name: "lines-ssh-ed25519", plain: text, ssh: ["test_ed25519"], openWith: { ssh: "test_ed25519" }, options: {} },
  { name: "lines-kdf-default", plain: "one line\n", password: "hunter2", openWith: { password: "hunter2" }, options: {} },
  { name: "blob-small-chunks", plain: seq(192), password: "hunter2", openWith: { password: "hunter2" }, options: { kdf: cheap, mode: "blob", chunk: 64 } },
  { name: "blob-partial-chunk", plain: seq(200, 5), password: "hunter2", openWith: { password: "hunter2" }, options: { kdf: cheap, mode: "blob", chunk: 64 } },
  { name: "blob-empty", plain: "", password: "hunter2", openWith: { password: "hunter2" }, options: { kdf: cheap, mode: "blob" } },
  { name: "blob-ssh-rsa", plain: seq(70000, 11), ssh: ["test_rsa"], openWith: { ssh: "test_rsa" }, options: { mode: "blob" } },
];
const manifest: unknown[] = [];
for (const v of vectors) {
  const keys: Key[] = [];
  if (v.password !== undefined) keys.push({ type: "password", password: v.password });
  for (const k of v.ssh ?? []) keys.push({ type: "ssh", publicKey: pub(k) });
  const dir = join(here, v.name);
  mkdirSync(dir, { recursive: true });
  const plain = typeof v.plain === "string" ? new TextEncoder().encode(v.plain) : v.plain;
  writeFileSync(join(dir, "plain.bin"), plain);
  writeFileSync(join(dir, "encrypted.txt"), await encrypt(plain, keys, v.options));
  manifest.push({ name: v.name, key: v.openWith });
}
writeFileSync(join(here, "vectors.json"), JSON.stringify(manifest, null, 2) + "\n");
console.log("wrote", vectors.length, "file vectors and primitives.json");
