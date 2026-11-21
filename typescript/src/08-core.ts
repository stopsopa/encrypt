import type { Bytes } from "./01-util.ts";
import { SsencError, ascii, b64urlDecodeBytes, b64urlEncode, concatBytes, constantTimeEqual, toBytes, u64be, utf8 } from "./01-util.ts";
import { argon2id } from "./03-argon2id.ts";
import type { SivKey } from "./04-prim.ts";
import { hkdf32, hmacSha256, randomBytes, sivDecrypt, sivEncrypt, sivKey } from "./04-prim.ts";
import type { KdfParams, ParsedFile, Slot } from "./05-format.ts";
import { headerLineFor, parseFile, parseKdf, slotLine } from "./05-format.ts";
import type { SshSigner } from "./06-ssh.ts";
import { sshFingerprint, sshKek, sshKeyType, sshParsePublicKey, sshRequireSupported } from "./06-ssh.ts";
import { agentFindKey, agentSign } from "./07-sshagent.node.ts";

// ---------------------------------------------------------------------------------------
// public types
// ---------------------------------------------------------------------------------------

export type PasswordKey = { type: "password"; password: string | Uint8Array };

export type SshKey = {
  type: "ssh";
  /** Content of an OpenSSH public key file ("ssh-ed25519 AAAA... comment"). */
  publicKey?: string;
  /** "SHA256:..." fingerprint of a key loaded in ssh-agent; used when publicKey is not given. */
  fingerprint?: string;
  /** Path of the agent socket; default is $SSH_AUTH_SOCK (Node.js build only). */
  agentSocket?: string;
  /** Replaces ssh-agent as the source of the signature; required in the browser build. */
  signer?: SshSigner;
};

export type Key = PasswordKey | SshKey;

export type EncryptOptions = {
  /** "lines" (default) encrypts line by line; "blob" encrypts the input as a whole. */
  mode?: "lines" | "blob";
  /** Lines mode: keep leading and trailing spaces/tabs of every line in clear. Default true. */
  preserveWhitespace?: boolean;
  /** Lines mode: pad every line to a multiple of this many bytes; 0 disables. Default 16. */
  pad?: number;
  /** Blob mode: chunk size in bytes. Default 65536. */
  chunk?: number;
  /** Argon2id cost for password slots: "default", "strong", "m=..,t=..,p=.." or an object. */
  kdf?: string | KdfParams;
  /** Previous encrypted version: its data key and slots are reused, so unchanged lines stay identical. */
  previous?: string | Uint8Array;
  /** Lines mode: add a MAC over the whole file. Default false. */
  seal?: boolean;
};

export type RekeyOptions = {
  /** true (default): re-encrypt everything under a new data key. false: only rewrap the data key. */
  rotateDataKey?: boolean;
  kdf?: string | KdfParams;
};

export type SlotInfo =
  | { type: "pw"; kdf: "argon2id"; m: number; t: number; p: number }
  | { type: "ssh"; keyType: string; fingerprint: string };

export type InspectResult =
  | { format: "ssenc1"; mode: "lines"; ws: boolean; pad: number; seal: boolean; slots: SlotInfo[] }
  | { format: "ssenc1"; mode: "blob"; chunk: number; slots: SlotInfo[] };

// ---------------------------------------------------------------------------------------
// key slots
// ---------------------------------------------------------------------------------------

const SLOT_AD: Bytes = utf8("ssenc1/slot");

function passwordBytes(key: PasswordKey): Bytes {
  const pw = toBytes(key.password);
  if (pw.length === 0) throw new SsencError("USAGE", "password must not be empty");
  return pw;
}

type ResolvedSsh = { blob: Bytes; keyType: string; fingerprint: string; signer: SshSigner };

async function resolveSsh(key: SshKey): Promise<ResolvedSsh> {
  let blob: Bytes;
  if (key.publicKey !== undefined) blob = sshParsePublicKey(key.publicKey);
  else if (key.fingerprint !== undefined) blob = await agentFindKey(key.agentSocket, key.fingerprint);
  else throw new SsencError("USAGE", "ssh key needs 'publicKey' or 'fingerprint'");
  const keyType = sshKeyType(blob);
  sshRequireSupported(keyType);
  const signer: SshSigner = key.signer ?? ((b, d) => agentSign(key.agentSocket, b, d));
  return { blob, keyType, fingerprint: await sshFingerprint(blob), signer };
}

async function wrapDek(kek: Uint8Array, dek: Uint8Array): Promise<Bytes> {
  return sivEncrypt(await sivKey(kek, "wrap"), SLOT_AD, dek);
}

async function makeSlots(keys: Key[], dek: Uint8Array, kdf: KdfParams): Promise<string[]> {
  if (keys.length === 0) throw new SsencError("USAGE", "at least one key is required");
  const lines: string[] = [];
  for (const key of keys) {
    if (key.type !== "password") continue;
    const salt = randomBytes(16);
    const kek = argon2id(passwordBytes(key), salt, kdf.m, kdf.t, kdf.p, 32);
    lines.push(slotLine({ type: "pw", m: kdf.m, t: kdf.t, p: kdf.p, salt, wrapped: await wrapDek(kek, dek) }));
  }
  for (const key of keys) {
    if (key.type !== "ssh") continue;
    const r = await resolveSsh(key);
    const salt = randomBytes(32);
    const kek = await sshKek(r.blob, salt, r.signer);
    lines.push(slotLine({ type: "ssh", keyType: r.keyType, fingerprint: r.fingerprint, salt, wrapped: await wrapDek(kek, dek) }));
  }
  return lines;
}

async function tryUnwrap(kek: Uint8Array, slot: Slot): Promise<Bytes | null> {
  try {
    return await sivDecrypt(await sivKey(kek, "wrap"), SLOT_AD, slot.wrapped);
  } catch (e) {
    if (e instanceof SsencError && e.kind === "AUTH") return null;
    throw e;
  }
}

/** Returns the data key, or null when no slot opens with this key. */
async function openWith(file: ParsedFile, key: Key): Promise<Bytes | null> {
  if (key.type === "password") {
    const pw = passwordBytes(key);
    for (const slot of file.slots) {
      if (slot.type !== "pw") continue;
      const dek = await tryUnwrap(argon2id(pw, slot.salt, slot.m, slot.t, slot.p, 32), slot);
      if (dek) return dek;
    }
    return null;
  }
  const r = await resolveSsh(key);
  for (const slot of file.slots) {
    if (slot.type !== "ssh" || slot.fingerprint !== r.fingerprint) continue;
    const dek = await tryUnwrap(await sshKek(r.blob, slot.salt, r.signer), slot);
    if (dek) return dek;
  }
  return null;
}

async function openOrFail(file: ParsedFile, keys: Key[]): Promise<Bytes> {
  if (keys.length === 0) throw new SsencError("USAGE", "at least one key is required");
  for (const key of keys) {
    const dek = await openWith(file, key);
    if (dek) return dek;
  }
  throw new SsencError("AUTH", "no key slot could be opened with the given key");
}

// ---------------------------------------------------------------------------------------
// lines mode (SPEC.md section 3)
// ---------------------------------------------------------------------------------------

function isWs(c: number): boolean {
  return c === 32 || c === 9;
}

/** Calls fn(contentStart, contentEnd, lineEnd) for every line; lineEnd includes the terminator. */
function eachLine(data: Uint8Array, fn: (start: number, end: number, next: number) => void): void {
  let pos = 0;
  while (pos < data.length) {
    const lf = data.indexOf(10, pos);
    if (lf < 0) {
      fn(pos, data.length, data.length);
      return;
    }
    fn(pos, lf > pos && data[lf - 1] === 13 ? lf - 1 : lf, lf + 1);
    pos = lf + 1;
  }
}

function padLine(x: Uint8Array, pad: number): Uint8Array {
  if (pad === 0) return x;
  const out = new Uint8Array((Math.floor(x.length / pad) + 1) * pad);
  out.set(x);
  out[x.length] = 0x80;
  return out;
}

function unpadLine(x: Uint8Array, pad: number): Uint8Array {
  if (pad === 0) return x;
  let n = x.length;
  while (n > 0 && x[n - 1] === 0) n--;
  if (n === 0 || x[n - 1] !== 0x80) throw new SsencError("MALFORMED", "invalid line padding");
  return x.subarray(0, n - 1);
}

const EMPTY: Bytes = new Uint8Array(0);

async function encryptLines(dek: Uint8Array, ws: boolean, pad: number, plain: Uint8Array): Promise<Bytes> {
  const key = await sivKey(dek, "line");
  const spans: number[] = [];
  eachLine(plain, (s, e, n) => spans.push(s, e, n));
  const parts: Uint8Array[] = [];
  for (let i = 0; i < spans.length; i += 3) {
    let s = spans[i];
    let e = spans[i + 1];
    const next = spans[i + 2];
    const lineStart = s;
    const lineEnd = e;
    if (ws) {
      while (s < e && isWs(plain[s])) s++;
      while (e > s && isWs(plain[e - 1])) e--;
      if (s === e) {
        parts.push(plain.subarray(lineStart, next));
        continue;
      }
    }
    const token = b64urlEncode(await sivEncrypt(key, EMPTY, padLine(plain.subarray(s, e), pad)));
    parts.push(plain.subarray(lineStart, s), utf8(token), plain.subarray(e, lineEnd), plain.subarray(lineEnd, next));
  }
  return concatBytes(...parts);
}

async function decryptLines(dek: Uint8Array, pad: number, body: Uint8Array): Promise<Bytes> {
  const key = await sivKey(dek, "line");
  const spans: number[] = [];
  eachLine(body, (s, e, n) => spans.push(s, e, n));
  const parts: Uint8Array[] = [];
  for (let i = 0; i < spans.length; i += 3) {
    let s = spans[i];
    let e = spans[i + 1];
    const next = spans[i + 2];
    const lineStart = s;
    const lineEnd = e;
    while (s < e && isWs(body[s])) s++;
    while (e > s && isWs(body[e - 1])) e--;
    if (s === e) {
      parts.push(body.subarray(lineStart, next));
      continue;
    }
    const raw = b64urlDecodeBytes(body.subarray(s, e));
    if (!raw || raw.length < 16) throw new SsencError("MALFORMED", "line " + (i / 3 + 1) + " is not a valid encrypted line");
    const plain = unpadLine(await sivDecrypt(key, EMPTY, raw), pad);
    parts.push(body.subarray(lineStart, s), plain, body.subarray(e, lineEnd), body.subarray(lineEnd, next));
  }
  return concatBytes(...parts);
}

async function sealFor(dek: Uint8Array, headerLine: string, body: Uint8Array): Promise<Bytes> {
  const k = await hkdf32(dek, null, "ssenc1/seal");
  return hmacSha256(k, concatBytes(utf8(headerLine), new Uint8Array([10]), body));
}

// ---------------------------------------------------------------------------------------
// blob mode (SPEC.md section 4)
// ---------------------------------------------------------------------------------------

function blobAd(index: number, final: boolean): Bytes {
  return concatBytes(u64be(index), new Uint8Array([final ? 1 : 0]));
}

async function encryptBlob(dek: Uint8Array, chunk: number, plain: Uint8Array): Promise<Bytes> {
  const key = await sivKey(dek, "blob");
  const records: Uint8Array[] = [];
  const count = Math.max(1, Math.ceil(plain.length / chunk));
  for (let i = 0; i < count; i++) {
    records.push(await sivEncrypt(key, blobAd(i, i === count - 1), plain.subarray(i * chunk, (i + 1) * chunk)));
  }
  const b64 = b64urlEncode(concatBytes(...records));
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += 76) lines.push(b64.slice(i, i + 76) + "\n");
  return utf8(lines.join(""));
}

async function decryptBlob(dek: Uint8Array, chunk: number, body: Uint8Array): Promise<Bytes> {
  const compact = new Uint8Array(body.length);
  let n = 0;
  for (let i = 0; i < body.length; i++) {
    const c = body[i];
    if (c !== 10 && c !== 13 && c !== 32 && c !== 9) compact[n++] = c;
  }
  const raw = b64urlDecodeBytes(compact.subarray(0, n));
  if (!raw || raw.length === 0) throw new SsencError("MALFORMED", "blob body is not valid base64url");
  const key = await sivKey(dek, "blob");
  const rec = chunk + 16;
  const count = Math.ceil(raw.length / rec);
  const parts: Uint8Array[] = [];
  for (let i = 0; i < count; i++) {
    parts.push(await sivDecrypt(key, blobAd(i, i === count - 1), raw.subarray(i * rec, (i + 1) * rec)));
  }
  return concatBytes(...parts);
}

// ---------------------------------------------------------------------------------------
// operations (SPEC.md section 5)
// ---------------------------------------------------------------------------------------

type Layout = { mode: "lines" | "blob"; ws: boolean; pad: number; chunk: number; seal: boolean };

function checkLayout(l: Layout): void {
  if (l.mode !== "lines" && l.mode !== "blob") throw new SsencError("USAGE", "mode must be 'lines' or 'blob'");
  if (!Number.isInteger(l.pad) || l.pad < 0 || l.pad > 4096) throw new SsencError("USAGE", "pad must be an integer from 0 to 4096");
  if (!Number.isInteger(l.chunk) || l.chunk < 1 || l.chunk > 1048576) throw new SsencError("USAGE", "chunk must be an integer from 1 to 1048576");
  if (l.seal && l.mode !== "lines") throw new SsencError("USAGE", "seal is only available in lines mode");
}

async function assemble(dek: Uint8Array, slotLines: string[], l: Layout, plain: Uint8Array): Promise<string> {
  const headerLine = headerLineFor(l.mode, l.ws, l.pad, l.chunk);
  const body = l.mode === "lines" ? await encryptLines(dek, l.ws, l.pad, plain) : await encryptBlob(dek, l.chunk, plain);
  let head = headerLine + "\n" + slotLines.map((s) => s + "\n").join("");
  if (l.seal) head += "#seal " + b64urlEncode(await sealFor(dek, headerLine, body)) + "\n";
  return head + ascii(body);
}

async function decryptParsed(file: ParsedFile, dek: Uint8Array): Promise<Bytes> {
  if (file.seal && !constantTimeEqual(file.seal, await sealFor(dek, file.headerLine, file.body))) {
    throw new SsencError("AUTH", "seal does not match: lines were added, removed, reordered or modified");
  }
  return file.mode === "lines" ? decryptLines(dek, file.pad, file.body) : decryptBlob(dek, file.chunk, file.body);
}

function keyList(key: Key | Key[]): Key[] {
  return Array.isArray(key) ? key : [key];
}

/** Encrypts bytes (or a string, as UTF-8) to ssenc1 ASCII text. */
export async function encrypt(input: Uint8Array | string, key: Key | Key[], options: EncryptOptions = {}): Promise<string> {
  const plain = toBytes(input);
  const keys = keyList(key);
  if (options.previous !== undefined) {
    const prev = parseFile(toBytes(options.previous));
    const dek = await openOrFail(prev, keys);
    const mode = options.mode ?? prev.mode;
    const layout: Layout = {
      mode,
      ws: options.preserveWhitespace ?? (prev.mode === "lines" ? prev.ws : true),
      pad: options.pad ?? (prev.mode === "lines" ? prev.pad : 16),
      chunk: options.chunk ?? (prev.mode === "blob" ? prev.chunk : 65536),
      seal: options.seal ?? (mode === "lines" && prev.seal !== null),
    };
    checkLayout(layout);
    return assemble(dek, prev.slotLines, layout, plain);
  }
  const layout: Layout = {
    mode: options.mode ?? "lines",
    ws: options.preserveWhitespace ?? true,
    pad: options.pad ?? 16,
    chunk: options.chunk ?? 65536,
    seal: options.seal ?? false,
  };
  checkLayout(layout);
  const kdf = parseKdf(options.kdf);
  const dek = randomBytes(32);
  return assemble(dek, await makeSlots(keys, dek, kdf), layout, plain);
}

/** Decrypts ssenc1 text and returns the original bytes. */
export async function decrypt(input: Uint8Array | string, key: Key): Promise<Bytes> {
  const file = parseFile(toBytes(input));
  return decryptParsed(file, await openOrFail(file, [key]));
}

/** Like decrypt, for input that was text: returns it as a string (UTF-8). */
export async function decryptToString(input: Uint8Array | string, key: Key): Promise<string> {
  return new TextDecoder().decode(await decrypt(input, key));
}

/** Replaces the keys of an encrypted text. */
export async function rekey(input: Uint8Array | string, oldKey: Key, newKey: Key | Key[], options: RekeyOptions = {}): Promise<string> {
  const file = parseFile(toBytes(input));
  const dek = await openOrFail(file, [oldKey]);
  const kdf = parseKdf(options.kdf);
  if (options.rotateDataKey === false) {
    const slots = await makeSlots(keyList(newKey), dek, kdf);
    let head = file.headerLine + "\n" + slots.map((s) => s + "\n").join("");
    if (file.seal) head += "#seal " + b64urlEncode(file.seal) + "\n";
    return head + ascii(file.body);
  }
  const plain = await decryptParsed(file, dek);
  const layout: Layout = {
    mode: file.mode, ws: file.ws, pad: file.mode === "lines" ? file.pad : 16,
    chunk: file.mode === "blob" ? file.chunk : 65536, seal: file.seal !== null,
  };
  const newDek = randomBytes(32);
  return assemble(newDek, await makeSlots(keyList(newKey), newDek, kdf), layout, plain);
}

/** Describes an encrypted text without needing a key. */
export function inspect(input: Uint8Array | string): InspectResult {
  const file = parseFile(toBytes(input));
  const slots: SlotInfo[] = file.slots.map((s) => s.type === "pw"
    ? { type: "pw", kdf: "argon2id", m: s.m, t: s.t, p: s.p }
    : { type: "ssh", keyType: s.keyType, fingerprint: s.fingerprint });
  if (file.mode === "lines") {
    return { format: "ssenc1", mode: "lines", ws: file.ws, pad: file.pad, seal: file.seal !== null, slots };
  }
  return { format: "ssenc1", mode: "blob", chunk: file.chunk, slots };
}

export const VERSION = "0.1.0";
