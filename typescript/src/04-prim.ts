import type { Bytes } from "./01-util.ts";
import { SsencError, concatBytes, constantTimeEqual, u64be, utf8 } from "./01-util.ts";

// ---------------------------------------------------------------------------------------
// WebCrypto primitives: HMAC-SHA-256, HKDF32, SIV (SPEC.md section 1)
// ---------------------------------------------------------------------------------------

const subtle: SubtleCrypto = globalThis.crypto.subtle;

export function randomBytes(n: number): Bytes {
  const out = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
  return out;
}

export async function sha256(data: Uint8Array): Promise<Bytes> {
  return new Uint8Array(await subtle.digest("SHA-256", data as BufferSource));
}

export async function sha512(data: Uint8Array): Promise<Bytes> {
  return new Uint8Array(await subtle.digest("SHA-512", data as BufferSource));
}

async function importHmacKey(key: Uint8Array): Promise<CryptoKey> {
  return subtle.importKey("raw", key as BufferSource, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
}

export async function hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Bytes> {
  return new Uint8Array(await subtle.sign("HMAC", await importHmacKey(key), data as BufferSource));
}

const ZERO32: Bytes = new Uint8Array(32);

/** HKDF-SHA-256 with a 32-byte output; salt null means 32 zero bytes. */
export async function hkdf32(ikm: Uint8Array, salt: Uint8Array | null, info: string): Promise<Bytes> {
  const prk = await hmacSha256(salt ?? ZERO32, ikm);
  return hmacSha256(prk, concatBytes(utf8(info), new Uint8Array([1])));
}

export type SivKey = { mac: CryptoKey; enc: CryptoKey };

export async function sivKey(parent: Uint8Array, purpose: string): Promise<SivKey> {
  const macRaw = await hkdf32(parent, null, "ssenc1/" + purpose + "-mac");
  const encRaw = await hkdf32(parent, null, "ssenc1/" + purpose + "-enc");
  return {
    mac: await importHmacKey(macRaw),
    enc: await subtle.importKey("raw", encRaw as BufferSource, { name: "AES-CTR" }, false, ["encrypt", "decrypt"]),
  };
}

async function sivTag(key: SivKey, ad: Uint8Array, pt: Uint8Array): Promise<Bytes> {
  const full = await subtle.sign("HMAC", key.mac, concatBytes(u64be(ad.length), ad, pt) as BufferSource);
  return new Uint8Array(full.slice(0, 16));
}

function sivIv(tag: Uint8Array): Bytes {
  const iv = new Uint8Array(16);
  iv.set(tag);
  iv[8] &= 0x7f;
  iv[12] &= 0x7f;
  return iv;
}

export async function sivEncrypt(key: SivKey, ad: Uint8Array, pt: Uint8Array): Promise<Bytes> {
  const tag = await sivTag(key, ad, pt);
  const ct = await subtle.encrypt({ name: "AES-CTR", counter: sivIv(tag), length: 64 }, key.enc, pt as BufferSource);
  return concatBytes(tag, new Uint8Array(ct));
}

export async function sivDecrypt(key: SivKey, ad: Uint8Array, input: Uint8Array): Promise<Bytes> {
  if (input.length < 16) throw new SsencError("MALFORMED", "ciphertext shorter than the authentication tag");
  const tag = input.subarray(0, 16);
  const pt = new Uint8Array(await subtle.decrypt(
    { name: "AES-CTR", counter: sivIv(tag), length: 64 }, key.enc, input.subarray(16) as BufferSource));
  if (!constantTimeEqual(tag, await sivTag(key, ad, pt))) {
    throw new SsencError("AUTH", "authentication failed (wrong key or modified data)");
  }
  return pt;
}
