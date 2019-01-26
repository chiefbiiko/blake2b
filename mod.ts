// Module blake2b implements the BLAKE2b hash algorithm defined by RFC 7693
// (https://tools.ietf.org/html/rfc7693).
// For a detailed specification of BLAKE2b see https://blake2.net/blake2.pdf

import { Reader, ReadResult, Writer } from "deno";
import { assert } from "./util.ts";

export const DIGESTBYTES_MIN = 1;
export const DIGESTBYTES_MAX = 64;
export const INPUTBYTES_MIN = 0;
export const INPUTBYTES_MAX = 2 ** 128 - 1;
export const KEYBYTES_MIN = 0;
export const KEYBYTES_MAX = 64;
export const SALTBYTES = 16;
export const PERSONALBYTES = 16;

// Creates a new Blake2b instance computing the BLAKE2b checksum with a custom
// length. Providing a key turns the hash into a MAC. The key must be between
// zero and 64 bytes long. The hash size can be a value between 1 and 64 but it
// is highly recommended to use values equal or greater than:
// - 32 if BLAKE2b is used as a hash function (key is zero bytes long).
// - 16 if BLAKE2b is used as a MAC function (key is at least 16 bytes long).
export class Blake2b implements Reader, Writer {
  // Initialization Vector
  static readonly IV32: Uint32Array = new Uint32Array([
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
  static readonly SIGMA8: number[] = [
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
  static readonly SIGMA82: Uint8Array = new Uint8Array(
    Blake2b.SIGMA8.map(function(x: number): number {
      return x * 2;
    })
  );

  public digestLength: number;
  // reusable working vector
  private v: Uint32Array = new Uint32Array(32);
  // reusable message block vector
  private m: Uint32Array = new Uint32Array(32);
  private b: Uint8Array;
  private h: Uint32Array;
  private t: number;
  private c: number;

  // reusable parameterBlock
  private parameterBlock: Uint8Array = new Uint8Array([
    0, 0, 0, 0,      //  0: digestLength, keylen, fanout, depth
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

  constructor(
    digestLength: number,
    key?: Uint8Array,
    salt?: Uint8Array,
    personal?: Uint8Array
  ) {
    assert(
      digestLength >= DIGESTBYTES_MIN,
      `actual digestLength ${digestLength}, valid min ${DIGESTBYTES_MIN}`
    );
    assert(
      digestLength <= DIGESTBYTES_MAX,
      `actual digest length ${digestLength}, valid max ${DIGESTBYTES_MAX}`
    );
    if (key) {
      assert(
        key.length >= KEYBYTES_MIN,
        `actual key length ${key.length}, valid min ${KEYBYTES_MIN}`
      );
      assert(
        key.length <= KEYBYTES_MAX,
        `actual key length ${key.length}, valid min ${KEYBYTES_MAX}`
      );
    }
    if (salt) {
      assert(
        salt.length === SALTBYTES,
        `actual salt length ${salt.length}, expected ${SALTBYTES}`
      );
    }
    if (personal) {
      assert(
        personal.length === PERSONALBYTES,
        `actual personal length ${personal.length}, ` +
          `expected ${PERSONALBYTES}`
      );
    }
    this.parameterBlock.fill(0); // zero out parameterBlock before usage
    this.b = new Uint8Array(128);
    this.h = new Uint32Array(16);
    this.t = 0; // input count
    this.c = 0; // pointer within buffer
    this.digestLength = digestLength; // output length in bytes
    this.parameterBlock[0] = digestLength;
    if (key) {
      this.parameterBlock[1] = key.length;
    }
    this.parameterBlock[2] = 1; // fanout
    this.parameterBlock[3] = 1; // depth
    if (salt) {
      this.parameterBlock.set(salt, 32);
    }
    if (personal) {
      this.parameterBlock.set(personal, 48);
    }
    for (let i: number = 0; i < 16; i++) {
      // initialize hash state
      this.h[i] =
        Blake2b.IV32[i] ^ Blake2b.B2B_GET32(this.parameterBlock, i * 4);
    }
    if (key) {
      // key the hash, if applicable
      this.blake2bUpdate(key);
      this.c = 128; // at the end
    }
  }

  public async write(input: Uint8Array): Promise<number> {
    assert(input != null, "input must be Uint8Array");
    assert(
      input.length >= INPUTBYTES_MIN,
      "input length must be greater than or equal to " + INPUTBYTES_MIN
    );
    assert(
      input.length <= INPUTBYTES_MAX,
      "input length must be less than or equal to " + INPUTBYTES_MAX
    );
    this.blake2bUpdate(input);
    return input.length;
  }

  public async read(out: Uint8Array): Promise<ReadResult> {
    assert(
      out.length >= this.digestLength,
      "out length must be greater than or equal " + this.digestLength
    );
    this.blake2bDigest(out);
    return { eof: true, nread: out.length };
  }

  // Little-endian byte access
  protected static B2B_GET32(arr: Uint8Array, i: number): number {
    return arr[i] ^ (arr[i + 1] << 8) ^ (arr[i + 2] << 16) ^ (arr[i + 3] << 24);
  }

  // 64-bit unsigned addition
  // Sets v[a,a+1] += v[b,b+1]
  private ADD64AA(v: Uint32Array, a: number, b: number): void {
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
  private ADD64AC(v: Uint32Array, a: number, b0: number, b1: number): void {
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

  // G Mixing function
  // The ROTRs are inlined for speed
  private B2B_G(
    a: number,
    b: number,
    c: number,
    d: number,
    ix: number,
    iy: number
  ): void {
    let x0: number = this.m[ix];
    let x1: number = this.m[ix + 1];
    let y0: number = this.m[iy];
    let y1: number = this.m[iy + 1];
    this.ADD64AA(this.v, a, b); // v[a,a+1] += v[b,b+1] ... in JS we must store a uint64 as two uint32s
    this.ADD64AC(this.v, a, x0, x1); // v[a, a+1] += x ... x0 is the low 32 bits of x, x1 is the high 32 bits
    // v[d,d+1] = (v[d,d+1] xor v[a,a+1]) rotated to the right by 32 bits
    let xor0: number = this.v[d] ^ this.v[a];
    let xor1: number = this.v[d + 1] ^ this.v[a + 1];
    this.v[d] = xor1;
    this.v[d + 1] = xor0;
    this.ADD64AA(this.v, c, d);
    // v[b,b+1] = (v[b,b+1] xor v[c,c+1]) rotated right by 24 bits
    xor0 = this.v[b] ^ this.v[c];
    xor1 = this.v[b + 1] ^ this.v[c + 1];
    this.v[b] = (xor0 >>> 24) ^ (xor1 << 8);
    this.v[b + 1] = (xor1 >>> 24) ^ (xor0 << 8);
    this.ADD64AA(this.v, a, b);
    this.ADD64AC(this.v, a, y0, y1);
    // v[d,d+1] = (v[d,d+1] xor v[a,a+1]) rotated right by 16 bits
    xor0 = this.v[d] ^ this.v[a];
    xor1 = this.v[d + 1] ^ this.v[a + 1];
    this.v[d] = (xor0 >>> 16) ^ (xor1 << 16);
    this.v[d + 1] = (xor1 >>> 16) ^ (xor0 << 16);
    this.ADD64AA(this.v, c, d);
    // v[b,b+1] = (v[b,b+1] xor v[c,c+1]) rotated right by 63 bits
    xor0 = this.v[b] ^ this.v[c];
    xor1 = this.v[b + 1] ^ this.v[c + 1];
    this.v[b] = (xor1 >>> 31) ^ (xor0 << 1);
    this.v[b + 1] = (xor0 >>> 31) ^ (xor1 << 1);
  }

  // Compression function. 'last' flag indicates last block.
  // Note we're representing 16 uint64s as 32 uint32s
  private blake2bCompress(last: boolean): void {
    let i: number = 0;
    // init work letiables
    for (i = 0; i < 16; i++) {
      this.v[i] = this.h[i];
      this.v[i + 16] = Blake2b.IV32[i];
    }
    // low 64 bits of offset
    this.v[24] = this.v[24] ^ this.t;
    this.v[25] = this.v[25] ^ (this.t / 0x100000000);
    // high 64 bits not supported, offset may not be higher than 2**53-1
    if (last) {
      // last block flag set ?
      this.v[28] = ~this.v[28];
      this.v[29] = ~this.v[29];
    }
    // get little-endian words
    for (i = 0; i < 32; i++) {
      this.m[i] = Blake2b.B2B_GET32(this.b, 4 * i);
    }
    // twelve rounds of mixing
    for (i = 0; i < 12; i++) {
      this.B2B_G(
        0,
        8,
        16,
        24,
        Blake2b.SIGMA82[i * 16 + 0],
        Blake2b.SIGMA82[i * 16 + 1]
      );
      this.B2B_G(
        2,
        10,
        18,
        26,
        Blake2b.SIGMA82[i * 16 + 2],
        Blake2b.SIGMA82[i * 16 + 3]
      );
      this.B2B_G(
        4,
        12,
        20,
        28,
        Blake2b.SIGMA82[i * 16 + 4],
        Blake2b.SIGMA82[i * 16 + 5]
      );
      this.B2B_G(
        6,
        14,
        22,
        30,
        Blake2b.SIGMA82[i * 16 + 6],
        Blake2b.SIGMA82[i * 16 + 7]
      );
      this.B2B_G(
        0,
        10,
        20,
        30,
        Blake2b.SIGMA82[i * 16 + 8],
        Blake2b.SIGMA82[i * 16 + 9]
      );
      this.B2B_G(
        2,
        12,
        22,
        24,
        Blake2b.SIGMA82[i * 16 + 10],
        Blake2b.SIGMA82[i * 16 + 11]
      );
      this.B2B_G(
        4,
        14,
        16,
        26,
        Blake2b.SIGMA82[i * 16 + 12],
        Blake2b.SIGMA82[i * 16 + 13]
      );
      this.B2B_G(
        6,
        8,
        18,
        28,
        Blake2b.SIGMA82[i * 16 + 14],
        Blake2b.SIGMA82[i * 16 + 15]
      );
    }
    for (i = 0; i < 16; i++) {
      this.h[i] = this.h[i] ^ this.v[i] ^ this.v[i + 16];
    }
  }

  // Updates a BLAKE2b streaming hash
  // Requires hash context and Uint8Array (byte array)
  private blake2bUpdate(input: Uint8Array): void {
    for (let i: number = 0; i < input.length; i++) {
      if (this.c === 128) {
        // buffer full ?
        this.t += this.c; // add counters
        this.blake2bCompress(false); // compress (not last)
        this.c = 0; // counter to zero
      }
      this.b[this.c++] = input[i];
    }
  }

  // Completes a BLAKE2b streaming hash
  private blake2bDigest(out: Uint8Array): void {
    this.t += this.c; // mark last block offset
    while (this.c < 128) {
      // fill up with zeros
      this.b[this.c++] = 0;
    }
    this.blake2bCompress(true); // final block flag = 1
    for (let i: number = 0; i < this.digestLength; i++) {
      out[i] = this.h[i >> 2] >> (8 * (i & 3));
    }
  }
}
