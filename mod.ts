// Module blake2b implements the BLAKE2b hash algorithm defined by RFC 7693
// (https://tools.ietf.org/html/rfc7693).
// For a detailed specification of BLAKE2b see https://blake2.net/blake2.pdf

import { Reader, ReadResult, Writer } from "deno";
import { toHexString } from "./util.ts";

export const DIGESTBYTES_MIN = 1;
export const DIGESTBYTES_MAX = 64;
export const INPUTBYTES_MIN = 0;
export const INPUTBYTES_MAX = 2 ** 128 - 1;
export const KEYBYTES_MIN = 0;
export const KEYBYTES_MAX = 64;
export const SALTBYTES = 16;
export const PERSONALBYTES = 16;

// Initialization Vector
const BLAKE2B_IV32: Uint32Array = new Uint32Array([
  0xf3bcc908,
  0x6a09e667,
  0x84caa73b,
  0xbb67ae85,
  0xfe94f82b,
  0x3c6ef372,
  0x5f1d36f1,
  0xa54ff53a,
  0xade682d1,
  0x510e527f,
  0x2b3e6c1f,
  0x9b05688c,
  0xfb41bd6b,
  0x1f83d9ab,
  0x137e2179,
  0x5be0cd19
]);

const SIGMA8: number[] = [
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
  11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
  7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
  9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
  2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
  12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
  13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
  6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
  10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3
];

// These are offsets into a uint64 buffer.
// Multiply them all by 2 to make them offsets into a uint32 buffer,
// because this is Javascript and we don't have uint64s
const SIGMA82: Uint8Array = new Uint8Array(
  SIGMA8.map(function(x: number): number {
    return x * 2;
  })
);

// reusable working vector
const v: Uint32Array = new Uint32Array(32);
// reusable message block vector
const m: Uint32Array = new Uint32Array(32);

// reusable parameter_block
const parameter_block: Uint8Array = new Uint8Array([
  0, 0, 0, 0,      //  0: outlen, keylen, fanout, depth
  0, 0, 0, 0,      //  4: leaf length, sequential mode
  0, 0, 0, 0,      //  8: node offset
  0, 0, 0, 0,      // 12: node offset
  0, 0, 0, 0,      // 16: node depth, inner length, rfu
  0, 0, 0, 0,      // 20: rfu
  0, 0, 0, 0,      // 24: rfu
  0, 0, 0, 0,      // 28: rfu
  0, 0, 0, 0,      // 32: salt
  0, 0, 0, 0,      // 36: salt
  0, 0, 0, 0,      // 40: salt
  0, 0, 0, 0,      // 44: salt
  0, 0, 0, 0,      // 48: personal
  0, 0, 0, 0,      // 52: personal
  0, 0, 0, 0,      // 56: personal
  0, 0, 0, 0       // 60: personal
]);

function assert(cond: boolean, msg: string = "Assertion failed"): void {
  if (!cond) {
    throw Error(msg);
  }
}

// 64-bit unsigned addition
// Sets v[a,a+1] += v[b,b+1]
// v should be a Uint32Array
function ADD64AA(v: Uint32Array, a: number, b: number): void {
  let o0: number = v[a] + v[b];
  let o1: number = v[a + 1] + v[b + 1];
  if (o0 >= 0x100000000) {
    o1++;
  }
  v[a] = o0;
  v[a + 1] = o1;
}

// 64-bit unsigned addition
// Sets v[a,a+1] += b
// b0 is the low 32 bits of b, b1 represents the high 32 bits
function ADD64AC(v: Uint32Array, a: number, b0: number, b1: number): void {
  let o0: number = v[a] + b0;
  if (b0 < 0) {
    o0 += 0x100000000;
  }
  let o1: number = v[a + 1] + b1;
  if (o0 >= 0x100000000) {
    o1++;
  }
  v[a] = o0;
  v[a + 1] = o1;
}

// Little-endian byte access
function B2B_GET32(arr: Uint8Array, i: number): number {
  return arr[i] ^ (arr[i + 1] << 8) ^ (arr[i + 2] << 16) ^ (arr[i + 3] << 24);
}

// G Mixing function
// The ROTRs are inlined for speed
function B2B_G(
  a: number,
  b: number,
  c: number,
  d: number,
  ix: number,
  iy: number
): void {
  let x0: number = m[ix];
  let x1: number = m[ix + 1];
  let y0: number = m[iy];
  let y1: number = m[iy + 1];

  ADD64AA(v, a, b); // v[a,a+1] += v[b,b+1] ... in JS we must store a uint64 as two uint32s
  ADD64AC(v, a, x0, x1); // v[a, a+1] += x ... x0 is the low 32 bits of x, x1 is the high 32 bits

  // v[d,d+1] = (v[d,d+1] xor v[a,a+1]) rotated to the right by 32 bits
  let xor0: number = v[d] ^ v[a];
  let xor1: number = v[d + 1] ^ v[a + 1];
  v[d] = xor1;
  v[d + 1] = xor0;

  ADD64AA(v, c, d);

  // v[b,b+1] = (v[b,b+1] xor v[c,c+1]) rotated right by 24 bits
  xor0 = v[b] ^ v[c];
  xor1 = v[b + 1] ^ v[c + 1];
  v[b] = (xor0 >>> 24) ^ (xor1 << 8);
  v[b + 1] = (xor1 >>> 24) ^ (xor0 << 8);

  ADD64AA(v, a, b);
  ADD64AC(v, a, y0, y1);

  // v[d,d+1] = (v[d,d+1] xor v[a,a+1]) rotated right by 16 bits
  xor0 = v[d] ^ v[a];
  xor1 = v[d + 1] ^ v[a + 1];
  v[d] = (xor0 >>> 16) ^ (xor1 << 16);
  v[d + 1] = (xor1 >>> 16) ^ (xor0 << 16);

  ADD64AA(v, c, d);

  // v[b,b+1] = (v[b,b+1] xor v[c,c+1]) rotated right by 63 bits
  xor0 = v[b] ^ v[c];
  xor1 = v[b + 1] ^ v[c + 1];
  v[b] = (xor1 >>> 31) ^ (xor0 << 1);
  v[b + 1] = (xor0 >>> 31) ^ (xor1 << 1);
}

// Compression function. 'last' flag indicates last block.
// Note we're representing 16 uint64s as 32 uint32s
function blake2bCompress(ctx: any, last: boolean): void {
  let i: number = 0;

  // init work letiables
  for (i = 0; i < 16; i++) {
    v[i] = ctx.h[i];
    v[i + 16] = BLAKE2B_IV32[i];
  }

  // low 64 bits of offset
  v[24] = v[24] ^ ctx.t;
  v[25] = v[25] ^ (ctx.t / 0x100000000);
  // high 64 bits not supported, offset may not be higher than 2**53-1

  // last block flag set ?
  if (last) {
    v[28] = ~v[28];
    v[29] = ~v[29];
  }

  // get little-endian words
  for (i = 0; i < 32; i++) {
    m[i] = B2B_GET32(ctx.b, 4 * i);
  }

  // twelve rounds of mixing
  for (i = 0; i < 12; i++) {
    B2B_G(0, 8, 16, 24, SIGMA82[i * 16 + 0], SIGMA82[i * 16 + 1]);
    B2B_G(2, 10, 18, 26, SIGMA82[i * 16 + 2], SIGMA82[i * 16 + 3]);
    B2B_G(4, 12, 20, 28, SIGMA82[i * 16 + 4], SIGMA82[i * 16 + 5]);
    B2B_G(6, 14, 22, 30, SIGMA82[i * 16 + 6], SIGMA82[i * 16 + 7]);
    B2B_G(0, 10, 20, 30, SIGMA82[i * 16 + 8], SIGMA82[i * 16 + 9]);
    B2B_G(2, 12, 22, 24, SIGMA82[i * 16 + 10], SIGMA82[i * 16 + 11]);
    B2B_G(4, 14, 16, 26, SIGMA82[i * 16 + 12], SIGMA82[i * 16 + 13]);
    B2B_G(6, 8, 18, 28, SIGMA82[i * 16 + 14], SIGMA82[i * 16 + 15]);
  }

  for (i = 0; i < 16; i++) {
    ctx.h[i] = ctx.h[i] ^ v[i] ^ v[i + 16];
  }
}

// Updates a BLAKE2b streaming hash
// Requires hash context and Uint8Array (byte array)
function blake2bUpdate(ctx: any, input: Uint8Array): void {
  for (let i: number = 0; i < input.length; i++) {
    if (ctx.c === 128) {
      // buffer full ?
      ctx.t += ctx.c; // add counters
      blake2bCompress(ctx, false); // compress (not last)
      ctx.c = 0; // counter to zero
    }
    ctx.b[ctx.c++] = input[i];
  }
}

// Completes a BLAKE2b streaming hash
// Returns a Uint8Array containing the message digest
function blake2bDigest(ctx: any, out: Uint8Array): void {
  ctx.t += ctx.c; // mark last block offset

  while (ctx.c < 128) {
    // fill up with zeros
    ctx.b[ctx.c++] = 0;
  }
  blake2bCompress(ctx, true); // final block flag = 1

  for (let i: number = 0; i < ctx.outlen; i++) {
    out[i] = ctx.h[i >> 2] >> (8 * (i & 3));
  }
}

// Creates a new Blake2b instance computing the BLAKE2b checksum with a custom
// length. Providing a key turns the hash into a MAC. The key must be between
// zero and 64 bytes long. The hash size can be a value between 1 and 64 but it
// is highly recommended to use values equal or greater than:
//   - 32 if BLAKE2b is used as a hash function (The key is zero bytes long).
//   - 16 if BLAKE2b is used as a MAC function (The key is at least 16 bytes long).
export class Blake2b implements Reader, Writer {
  b: Uint8Array;
  h: Uint32Array;
  t: number;
  c: number;
  outlen: number;
  constructor(
    outlen: number,
    key?: Uint8Array,
    salt?: Uint8Array,
    personal?: Uint8Array
  ) {
    assert(
      outlen >= DIGESTBYTES_MIN,
      "outlen must be at least " + DIGESTBYTES_MIN + ", was given " + outlen
    );
    assert(
      outlen <= DIGESTBYTES_MAX,
      "outlen must be at most " + DIGESTBYTES_MAX + ", was given " + outlen
    );
    if (key) {
      assert(
        key.length >= KEYBYTES_MIN,
        "key must be at least " + KEYBYTES_MIN + ", was given " + key.length
      );
      assert(
        key.length <= KEYBYTES_MAX,
        "key must be at most " + KEYBYTES_MAX + ", was given " + key.length
      );
    }
    if (salt) {
      assert(
        salt.length === SALTBYTES,
        "salt must be exactly " + SALTBYTES + ", was given " + salt.length
      );
    }
    if (personal) {
      assert(
        personal.length === PERSONALBYTES,
        "personal must be exactly " +
          PERSONALBYTES +
          ", was given " +
          personal.length
      );
    }
    parameter_block.fill(0); // zero out parameter_block before usage
    this.b = new Uint8Array(128);
    this.h = new Uint32Array(16);
    this.t = 0; // input count
    this.c = 0; // pointer within buffer
    this.outlen = outlen; // output length in bytes
    parameter_block[0] = outlen;
    if (key) {
      parameter_block[1] = key.length;
    }
    parameter_block[2] = 1; // fanout
    parameter_block[3] = 1; // depth
    if (salt) {
      parameter_block.set(salt, 32);
    }
    if (personal) {
      parameter_block.set(personal, 48);
    }
    for (let i: number = 0; i < 16; i++) { // initialize hash state
      this.h[i] = BLAKE2B_IV32[i] ^ B2B_GET32(parameter_block, i * 4);
    }
    if (key) { // key the hash, if applicable
      blake2bUpdate(this, key);
      this.c = 128; // at the end
    }
  }
  async write(input: Uint8Array): Promise<number> {
    assert(input != null, "input must be Uint8Array");
    assert(
      input.length >= INPUTBYTES_MIN,
      "input length must be greater than or equal to " + INPUTBYTES_MIN
    );
    assert(
      input.length <= INPUTBYTES_MAX,
      "input length must be less than or equal to " + INPUTBYTES_MAX
    );
    blake2bUpdate(this, input);
    return input.length;
  }
  async read(out: Uint8Array): Promise<ReadResult> {
    assert(
      out.length >= this.outlen,
      "out length must be greater than or equal " + this.outlen
    );
    blake2bDigest(this, out);
    return { eof: true, nread: out.length };
  }
}
