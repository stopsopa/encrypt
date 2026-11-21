// ---------------------------------------------------------------------------------------
// errors and byte helpers
// ---------------------------------------------------------------------------------------

export type SsencErrorKind = "USAGE" | "AUTH" | "MALFORMED" | "ENV";

export class SsencError extends Error {
  kind: SsencErrorKind;
  constructor(kind: SsencErrorKind, message: string) {
    super(message);
    this.name = "SsencError";
    this.kind = kind;
  }
}

export type Bytes = Uint8Array<ArrayBuffer>;

const textEncoder = new TextEncoder();

export function utf8(s: string): Bytes {
  return textEncoder.encode(s) as Bytes;
}

export function ascii(b: Uint8Array): string {
  let out = "";
  for (let i = 0; i < b.length; i += 8192) {
    out += String.fromCharCode.apply(null, b.subarray(i, i + 8192) as unknown as number[]);
  }
  return out;
}

export function toBytes(x: Uint8Array | string): Bytes {
  if (typeof x === "string") return utf8(x);
  const out = new Uint8Array(x.length);
  out.set(x);
  return out;
}

export function concatBytes(...parts: Uint8Array[]): Bytes {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function u32be(n: number): Bytes {
  return new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
}

export function u64be(n: number): Bytes {
  const out = new Uint8Array(8);
  out.set(u32be(Math.floor(n / 4294967296)), 0);
  out.set(u32be(n >>> 0), 4);
  return out;
}

export function sshString(b: Uint8Array): Bytes {
  return concatBytes(u32be(b.length), b);
}

export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

const B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const B64STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64URL_REV = new Int8Array(128).fill(-1);
for (let i = 0; i < 64; i++) B64URL_REV[B64URL.charCodeAt(i)] = i;

function b64encodeWith(alphabet: string, b: Uint8Array): string {
  const parts: string[] = [];
  let s = "";
  const n = b.length;
  let i = 0;
  for (; i + 2 < n; i += 3) {
    const v = (b[i] << 16) | (b[i + 1] << 8) | b[i + 2];
    s += alphabet[v >>> 18] + alphabet[(v >>> 12) & 63] + alphabet[(v >>> 6) & 63] + alphabet[v & 63];
    if (s.length >= 16384) {
      parts.push(s);
      s = "";
    }
  }
  if (n - i === 1) {
    const v = b[i] << 16;
    s += alphabet[v >>> 18] + alphabet[(v >>> 12) & 63];
  } else if (n - i === 2) {
    const v = (b[i] << 16) | (b[i + 1] << 8);
    s += alphabet[v >>> 18] + alphabet[(v >>> 12) & 63] + alphabet[(v >>> 6) & 63];
  }
  parts.push(s);
  return parts.join("");
}

/** RFC 4648 section 5 base64url without padding. */
export function b64urlEncode(b: Uint8Array): string {
  return b64encodeWith(B64URL, b);
}

/** Standard base64 without padding (ssh fingerprints). */
export function b64stdEncodeNoPad(b: Uint8Array): string {
  return b64encodeWith(B64STD, b);
}

/** Decodes unpadded base64url given as bytes; returns null when it is not valid. */
export function b64urlDecodeBytes(s: Uint8Array): Bytes | null {
  const n = s.length;
  if (n % 4 === 1) return null;
  const out = new Uint8Array(Math.floor((n * 3) / 4));
  let o = 0;
  let acc = 0;
  let bits = 0;
  for (let i = 0; i < n; i++) {
    const c = s[i];
    const v = c < 128 ? B64URL_REV[c] : -1;
    if (v < 0) return null;
    acc = ((acc << 6) | v) & 0xffffff;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >>> bits) & 255;
    }
  }
  return out;
}

export function b64urlDecode(s: string): Bytes | null {
  return b64urlDecodeBytes(utf8(s));
}

/** Standard base64 (with or without padding), used only for ssh public key lines. */
export function b64stdDecode(s: string): Bytes | null {
  const t = s.replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
  return b64urlDecode(t);
}
