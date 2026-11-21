import type { Bytes } from "./01-util.ts";
import { concatBytes } from "./01-util.ts";
import { blake2b } from "./02-blake2b.ts";

// ---------------------------------------------------------------------------------------
// Argon2id v1.3 (RFC 9106). 64-bit words are kept as two 32-bit halves in a Uint32Array
// (little-endian: low half first), which is what makes it usably fast in JavaScript.
// ---------------------------------------------------------------------------------------

function argon2Le32(n: number): Bytes {
  return new Uint8Array([n & 255, (n >>> 8) & 255, (n >>> 16) & 255, (n >>> 24) & 255]);
}

/** H' of RFC 9106 section 3.3: BLAKE2b with arbitrary output length. */
function argon2HashLong(input: Uint8Array, outLen: number): Bytes {
  const prefixed = concatBytes(argon2Le32(outLen), input);
  if (outLen <= 64) return blake2b(prefixed, outLen);
  const r = Math.ceil(outLen / 32) - 2;
  const out = new Uint8Array(outLen);
  let v = blake2b(prefixed, 64);
  out.set(v.subarray(0, 32), 0);
  for (let i = 1; i < r; i++) {
    v = blake2b(v, 64);
    out.set(v.subarray(0, 32), i * 32);
  }
  out.set(blake2b(v, outLen - 32 * r), r * 32);
  return out;
}

/** One BlaMka quarter round on 64-bit words at word indices a, b, c, d of v. */
function argon2GB(v: Uint32Array, a: number, b: number, c: number, d: number): void {
  a <<= 1;
  b <<= 1;
  c <<= 1;
  d <<= 1;
  let al = v[a], ah = v[a + 1], bl = v[b], bh = v[b + 1];
  let cl = v[c], ch = v[c + 1], dl = v[d], dh = v[d + 1];
  let x0: number, x1: number, y0: number, y1: number, t: number, w0: number, w2: number;
  let pl: number, ph: number, lo: number, tmp: number;

  // a = a + b + 2 * lo(a) * lo(b)
  x0 = al & 0xffff; x1 = al >>> 16; y0 = bl & 0xffff; y1 = bl >>> 16;
  t = x0 * y0; w0 = t & 0xffff; t = x1 * y0 + (t >>> 16); w2 = t >>> 16;
  t = x0 * y1 + (t & 0xffff);
  ph = x1 * y1 + w2 + (t >>> 16); pl = (((t & 0xffff) << 16) | w0) >>> 0;
  ph = ((ph << 1) | (pl >>> 31)) >>> 0; pl = (pl << 1) >>> 0;
  lo = al + bl + pl; al = lo >>> 0; ah = (ah + bh + ph + Math.floor(lo / 4294967296)) >>> 0;
  // d = rotr(d ^ a, 32)
  tmp = dl ^ al; dl = (dh ^ ah) >>> 0; dh = tmp >>> 0;
  // c = c + d + 2 * lo(c) * lo(d)
  x0 = cl & 0xffff; x1 = cl >>> 16; y0 = dl & 0xffff; y1 = dl >>> 16;
  t = x0 * y0; w0 = t & 0xffff; t = x1 * y0 + (t >>> 16); w2 = t >>> 16;
  t = x0 * y1 + (t & 0xffff);
  ph = x1 * y1 + w2 + (t >>> 16); pl = (((t & 0xffff) << 16) | w0) >>> 0;
  ph = ((ph << 1) | (pl >>> 31)) >>> 0; pl = (pl << 1) >>> 0;
  lo = cl + dl + pl; cl = lo >>> 0; ch = (ch + dh + ph + Math.floor(lo / 4294967296)) >>> 0;
  // b = rotr(b ^ c, 24)
  x0 = bl ^ cl; x1 = bh ^ ch;
  bl = ((x0 >>> 24) | (x1 << 8)) >>> 0; bh = ((x1 >>> 24) | (x0 << 8)) >>> 0;
  // a = a + b + 2 * lo(a) * lo(b)
  x0 = al & 0xffff; x1 = al >>> 16; y0 = bl & 0xffff; y1 = bl >>> 16;
  t = x0 * y0; w0 = t & 0xffff; t = x1 * y0 + (t >>> 16); w2 = t >>> 16;
  t = x0 * y1 + (t & 0xffff);
  ph = x1 * y1 + w2 + (t >>> 16); pl = (((t & 0xffff) << 16) | w0) >>> 0;
  ph = ((ph << 1) | (pl >>> 31)) >>> 0; pl = (pl << 1) >>> 0;
  lo = al + bl + pl; al = lo >>> 0; ah = (ah + bh + ph + Math.floor(lo / 4294967296)) >>> 0;
  // d = rotr(d ^ a, 16)
  x0 = dl ^ al; x1 = dh ^ ah;
  dl = ((x0 >>> 16) | (x1 << 16)) >>> 0; dh = ((x1 >>> 16) | (x0 << 16)) >>> 0;
  // c = c + d + 2 * lo(c) * lo(d)
  x0 = cl & 0xffff; x1 = cl >>> 16; y0 = dl & 0xffff; y1 = dl >>> 16;
  t = x0 * y0; w0 = t & 0xffff; t = x1 * y0 + (t >>> 16); w2 = t >>> 16;
  t = x0 * y1 + (t & 0xffff);
  ph = x1 * y1 + w2 + (t >>> 16); pl = (((t & 0xffff) << 16) | w0) >>> 0;
  ph = ((ph << 1) | (pl >>> 31)) >>> 0; pl = (pl << 1) >>> 0;
  lo = cl + dl + pl; cl = lo >>> 0; ch = (ch + dh + ph + Math.floor(lo / 4294967296)) >>> 0;
  // b = rotr(b ^ c, 63)
  x0 = bl ^ cl; x1 = bh ^ ch;
  bl = ((x0 << 1) | (x1 >>> 31)) >>> 0; bh = ((x1 << 1) | (x0 >>> 31)) >>> 0;

  v[a] = al; v[a + 1] = ah; v[b] = bl; v[b + 1] = bh;
  v[c] = cl; v[c + 1] = ch; v[d] = dl; v[d + 1] = dh;
}

function argon2P(v: Uint32Array, i0: number, i1: number, i2: number, i3: number, i4: number,
  i5: number, i6: number, i7: number, i8: number, i9: number, i10: number, i11: number,
  i12: number, i13: number, i14: number, i15: number): void {
  argon2GB(v, i0, i4, i8, i12);
  argon2GB(v, i1, i5, i9, i13);
  argon2GB(v, i2, i6, i10, i14);
  argon2GB(v, i3, i7, i11, i15);
  argon2GB(v, i0, i5, i10, i15);
  argon2GB(v, i1, i6, i11, i12);
  argon2GB(v, i2, i7, i8, i13);
  argon2GB(v, i3, i4, i9, i14);
}

const ARGON2_BLOCK_U32 = 256;

/** dst = G(x, y), optionally XORed into the previous content of dst. All are 256 u32. */
function argon2Compress(mem: Uint32Array, xOff: number, yOff: number, dstOff: number,
  xorInto: boolean, r: Uint32Array, z: Uint32Array): void {
  for (let i = 0; i < ARGON2_BLOCK_U32; i++) {
    r[i] = mem[xOff + i] ^ mem[yOff + i];
    z[i] = r[i];
  }
  for (let i = 0; i < 128; i += 16) {
    argon2P(z, i, i + 1, i + 2, i + 3, i + 4, i + 5, i + 6, i + 7, i + 8, i + 9, i + 10,
      i + 11, i + 12, i + 13, i + 14, i + 15);
  }
  for (let i = 0; i < 16; i += 2) {
    argon2P(z, i, i + 1, i + 16, i + 17, i + 32, i + 33, i + 48, i + 49, i + 64, i + 65,
      i + 80, i + 81, i + 96, i + 97, i + 112, i + 113);
  }
  if (xorInto) {
    for (let i = 0; i < ARGON2_BLOCK_U32; i++) mem[dstOff + i] ^= r[i] ^ z[i];
  } else {
    for (let i = 0; i < ARGON2_BLOCK_U32; i++) mem[dstOff + i] = r[i] ^ z[i];
  }
}

export function argon2id(password: Uint8Array, salt: Uint8Array, memoryKiB: number,
  iterations: number, parallelism: number, outLen: number): Bytes {
  const p = parallelism;
  const laneLen = Math.floor(memoryKiB / (4 * p)) * 4;
  const segLen = laneLen / 4;
  const total = laneLen * p;

  const h0 = blake2b(concatBytes(
    argon2Le32(p), argon2Le32(outLen), argon2Le32(memoryKiB), argon2Le32(iterations),
    argon2Le32(0x13), argon2Le32(2),
    argon2Le32(password.length), password, argon2Le32(salt.length), salt,
    argon2Le32(0), argon2Le32(0)), 64);

  const mem = new Uint32Array(total * ARGON2_BLOCK_U32);
  const loadBlock = (bytes: Uint8Array, blockIndex: number): void => {
    const view = new DataView(bytes.buffer, bytes.byteOffset, 1024);
    const off = blockIndex * ARGON2_BLOCK_U32;
    for (let i = 0; i < ARGON2_BLOCK_U32; i++) mem[off + i] = view.getUint32(i * 4, true);
  };
  for (let lane = 0; lane < p; lane++) {
    loadBlock(argon2HashLong(concatBytes(h0, argon2Le32(0), argon2Le32(lane)), 1024), lane * laneLen);
    loadBlock(argon2HashLong(concatBytes(h0, argon2Le32(1), argon2Le32(lane)), 1024), lane * laneLen + 1);
  }

  const r = new Uint32Array(ARGON2_BLOCK_U32);
  const z = new Uint32Array(ARGON2_BLOCK_U32);
  // scratch for data-independent addressing: [zero block, input block, address block]
  const addr = new Uint32Array(3 * ARGON2_BLOCK_U32);
  const ADDR_IN = ARGON2_BLOCK_U32;
  const ADDR_OUT = 2 * ARGON2_BLOCK_U32;

  for (let pass = 0; pass < iterations; pass++) {
    for (let slice = 0; slice < 4; slice++) {
      const independent = pass === 0 && slice < 2;
      for (let lane = 0; lane < p; lane++) {
        let counter = 0;
        const nextAddresses = (): void => {
          counter++;
          addr.fill(0, ADDR_IN, ADDR_IN + ARGON2_BLOCK_U32);
          addr[ADDR_IN + 0] = pass;
          addr[ADDR_IN + 2] = lane;
          addr[ADDR_IN + 4] = slice;
          addr[ADDR_IN + 6] = total;
          addr[ADDR_IN + 8] = iterations;
          addr[ADDR_IN + 10] = 2;
          addr[ADDR_IN + 12] = counter;
          argon2Compress(addr, 0, ADDR_IN, ADDR_OUT, false, r, z);
          argon2Compress(addr, 0, ADDR_OUT, ADDR_OUT, false, r, z);
        };
        let start = 0;
        if (pass === 0 && slice === 0) {
          start = 2;
          if (independent) nextAddresses();
        }
        for (let index = start; index < segLen; index++) {
          const cur = lane * laneLen + slice * segLen + index;
          const prev = cur % laneLen === 0 ? cur + laneLen - 1 : cur - 1;
          let j1: number, j2: number;
          if (independent) {
            if (index % 128 === 0) nextAddresses();
            j1 = addr[ADDR_OUT + (index % 128) * 2];
            j2 = addr[ADDR_OUT + (index % 128) * 2 + 1];
          } else {
            j1 = mem[prev * ARGON2_BLOCK_U32];
            j2 = mem[prev * ARGON2_BLOCK_U32 + 1];
          }
          let refLane = j2 % p;
          if (pass === 0 && slice === 0) refLane = lane;
          const sameLane = refLane === lane;
          let area: number;
          if (pass === 0) {
            if (slice === 0) area = index - 1;
            else if (sameLane) area = slice * segLen + index - 1;
            else area = slice * segLen + (index === 0 ? -1 : 0);
          } else if (sameLane) area = laneLen - segLen + index - 1;
          else area = laneLen - segLen + (index === 0 ? -1 : 0);
          // rel = area - 1 - ((area * ((j1 * j1) >> 32)) >> 32), with exact 64-bit products
          const x = Number((BigInt(j1) * BigInt(j1)) >> 32n);
          const y = Number((BigInt(area) * BigInt(x)) >> 32n);
          const rel = area - 1 - y;
          const startPos = pass !== 0 && slice !== 3 ? (slice + 1) * segLen : 0;
          const ref = refLane * laneLen + ((startPos + rel) % laneLen);
          argon2Compress(mem, prev * ARGON2_BLOCK_U32, ref * ARGON2_BLOCK_U32,
            cur * ARGON2_BLOCK_U32, pass !== 0, r, z);
        }
      }
    }
  }

  const fin = new Uint32Array(ARGON2_BLOCK_U32);
  for (let lane = 0; lane < p; lane++) {
    const off = (lane * laneLen + laneLen - 1) * ARGON2_BLOCK_U32;
    for (let i = 0; i < ARGON2_BLOCK_U32; i++) fin[i] ^= mem[off + i];
  }
  const finBytes = new Uint8Array(1024);
  const view = new DataView(finBytes.buffer);
  for (let i = 0; i < ARGON2_BLOCK_U32; i++) view.setUint32(i * 4, fin[i], true);
  return argon2HashLong(finBytes, outLen);
}
