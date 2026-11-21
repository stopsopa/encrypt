import type { Bytes } from "./01-util.ts";

// ---------------------------------------------------------------------------------------
// BLAKE2b (RFC 7693), unkeyed. Only used by Argon2id for a handful of hashes, so it is
// written for clarity with BigInt rather than for speed.
// ---------------------------------------------------------------------------------------

const BLAKE2B_IV: bigint[] = [
  0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n,
];

const BLAKE2B_SIGMA: number[][] = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

const MASK64 = 0xffffffffffffffffn;

function blake2bRotr(x: bigint, n: bigint): bigint {
  return ((x >> n) | (x << (64n - n))) & MASK64;
}

function blake2bCompress(h: bigint[], block: Uint8Array, t: bigint, last: boolean): void {
  const m: bigint[] = new Array(16);
  const view = new DataView(block.buffer, block.byteOffset, 128);
  for (let i = 0; i < 16; i++) m[i] = view.getBigUint64(i * 8, true);
  const v: bigint[] = [...h, ...BLAKE2B_IV];
  v[12] ^= t & MASK64;
  v[13] ^= t >> 64n;
  if (last) v[14] ^= MASK64;
  const g = (a: number, b: number, c: number, d: number, x: bigint, y: bigint): void => {
    v[a] = (v[a] + v[b] + x) & MASK64;
    v[d] = blake2bRotr(v[d] ^ v[a], 32n);
    v[c] = (v[c] + v[d]) & MASK64;
    v[b] = blake2bRotr(v[b] ^ v[c], 24n);
    v[a] = (v[a] + v[b] + y) & MASK64;
    v[d] = blake2bRotr(v[d] ^ v[a], 16n);
    v[c] = (v[c] + v[d]) & MASK64;
    v[b] = blake2bRotr(v[b] ^ v[c], 63n);
  };
  for (let r = 0; r < 12; r++) {
    const s = BLAKE2B_SIGMA[r];
    g(0, 4, 8, 12, m[s[0]], m[s[1]]);
    g(1, 5, 9, 13, m[s[2]], m[s[3]]);
    g(2, 6, 10, 14, m[s[4]], m[s[5]]);
    g(3, 7, 11, 15, m[s[6]], m[s[7]]);
    g(0, 5, 10, 15, m[s[8]], m[s[9]]);
    g(1, 6, 11, 12, m[s[10]], m[s[11]]);
    g(2, 7, 8, 13, m[s[12]], m[s[13]]);
    g(3, 4, 9, 14, m[s[14]], m[s[15]]);
  }
  for (let i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i + 8];
}

export function blake2b(data: Uint8Array, outLen: number): Bytes {
  const h = BLAKE2B_IV.slice();
  h[0] ^= 0x01010000n ^ BigInt(outLen);
  const block = new Uint8Array(128);
  let off = 0;
  while (data.length - off > 128) {
    block.set(data.subarray(off, off + 128));
    off += 128;
    blake2bCompress(h, block, BigInt(off), false);
  }
  block.fill(0);
  block.set(data.subarray(off));
  blake2bCompress(h, block, BigInt(data.length), true);
  const full = new Uint8Array(64);
  const view = new DataView(full.buffer);
  for (let i = 0; i < 8; i++) view.setBigUint64(i * 8, h[i], true);
  return full.slice(0, outLen);
}
