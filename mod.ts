import { assert } from "https://deno.land/x/testing/asserts.ts";

/**
 * @classdesc Class Blake2b implements BLAKE2b as specified in RFC 7693
 *   (https://tools.ietf.org/html/rfc7693). It implements the deno.Reader and
 *   deno.Writer interfaces to offer a straightforward and unambigious API for
 *   updating and finalizing a hash.
 */
export class Blake2b implements Deno.Reader, Deno.Writer {
  // Constant parameters
  public static readonly BYTES_MIN = 1;
  public static readonly BYTES_MAX = 64;
  public static readonly INPUTBYTES_MIN = 0;
  public static readonly INPUTBYTES_MAX = 2n ** 128n - 1n;
  public static readonly KEYBYTES_MIN = 0;
  public static readonly KEYBYTES_MAX = 64;
  public static readonly SALTBYTES = 16;
  public static readonly PERSONALBYTES = 16;

  // Initialization Vector
  protected static readonly IV32: Uint32Array = new Uint32Array([
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

  protected static readonly SIGMA8: number[] = [
    0,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    12,
    13,
    14,
    15,
    14,
    10,
    4,
    8,
    9,
    15,
    13,
    6,
    1,
    12,
    0,
    2,
    11,
    7,
    5,
    3,
    11,
    8,
    12,
    0,
    5,
    2,
    15,
    13,
    10,
    14,
    3,
    6,
    7,
    1,
    9,
    4,
    7,
    9,
    3,
    1,
    13,
    12,
    11,
    14,
    2,
    6,
    5,
    10,
    4,
    0,
    15,
    8,
    9,
    0,
    5,
    7,
    2,
    4,
    10,
    15,
    14,
    1,
    11,
    12,
    6,
    8,
    3,
    13,
    2,
    12,
    6,
    10,
    0,
    11,
    8,
    3,
    4,
    13,
    7,
    5,
    15,
    14,
    1,
    9,
    12,
    5,
    1,
    15,
    14,
    13,
    4,
    10,
    0,
    7,
    6,
    3,
    9,
    2,
    8,
    11,
    13,
    11,
    7,
    14,
    12,
    1,
    3,
    9,
    5,
    0,
    15,
    4,
    8,
    6,
    2,
    10,
    6,
    15,
    14,
    9,
    11,
    3,
    0,
    8,
    12,
    2,
    13,
    7,
    1,
    4,
    10,
    5,
    10,
    2,
    8,
    4,
    7,
    6,
    1,
    5,
    15,
    11,
    9,
    14,
    3,
    12,
    13,
    0,
    0,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    12,
    13,
    14,
    15,
    14,
    10,
    4,
    8,
    9,
    15,
    13,
    6,
    1,
    12,
    0,
    2,
    11,
    7,
    5,
    3
  ];

  // These are offsets into a uint64 buffer.
  // Multiply them all by 2 to make them offsets into a uint32 buffer,
  // because this is Javascript and we don't have uint64s
  protected static readonly SIGMA82: Uint8Array = new Uint8Array(
    Blake2b.SIGMA8.map(function(x: number): number {
      return x * 2;
    })
  );

  public readonly bytes: number;
  private v: Uint32Array = new Uint32Array(32); // reusable working vector
  private m: Uint32Array = new Uint32Array(32); // reusable message block vector
  private b: Uint8Array = new Uint8Array(128);
  private h: Uint32Array = new Uint32Array(16);
  private t: number = 0; // input count
  private c: number = 0; // pointer within buffer

  // reusable parameterBlock
  private parameterBlock: Uint8Array = new Uint8Array([
    0,
    0,
    0,
    0, //  0: bytes, keylen, fanout, depth
    0,
    0,
    0,
    0, //  4: leaf length, sequential mode
    0,
    0,
    0,
    0, //  8: node offset
    0,
    0,
    0,
    0, // 12: node offset
    0,
    0,
    0,
    0, // 16: node depth, inner length, rfu
    0,
    0,
    0,
    0, // 20: rfu
    0,
    0,
    0,
    0, // 24: rfu
    0,
    0,
    0,
    0, // 28: rfu
    0,
    0,
    0,
    0, // 32: salt
    0,
    0,
    0,
    0, // 36: salt
    0,
    0,
    0,
    0, // 40: salt
    0,
    0,
    0,
    0, // 44: salt
    0,
    0,
    0,
    0, // 48: personal
    0,
    0,
    0,
    0, // 52: personal
    0,
    0,
    0,
    0, // 56: personal
    0,
    0,
    0,
    0 // 60: personal
  ]);

  /**
   * Creates a new Blake2b instance computing the BLAKE2b checksum with a custom
   * length. Providing a key turns the hash into a MAC. The key must be between
   *  zero and 64 bytes long. The hash size can be a value between 1 and 64 but
   * it is highly recommended to use values equal or greater than:
   *   - 32 if BLAKE2b is used as a hash function (key is zero bytes long).
   *   - 16 if BLAKE2b is used as a MAC function (key is at least 16 bytes long).
   * @constructor
   * @param {number} bytes - Digest length. Must be inbetween
   *   Blake2b.BYTES_MIN and Blake2b.BYTES_MAX.
   * @param {Uint8Array} [key] - Key length must be inbetween
   *  Blake2b.KEYBYTES_MIN and Blake2b.KEYBYTES_MAX
   * @param {Uint8Array} [salt] - Must be Blake2b.SALTBYTES long.
   * @param {Uint8Array} [personal] - Must be Blake2b.PERSONALBYTES long.
   */
  public constructor(
    bytes: number,
    key?: Uint8Array,
    salt?: Uint8Array,
    personal?: Uint8Array
  ) {
    assert(
      bytes >= Blake2b.BYTES_MIN,
      `actual digest length ${bytes}, min ${Blake2b.BYTES_MIN}`
    );
    assert(
      bytes <= Blake2b.BYTES_MAX,
      `actual digest length ${bytes}, max ${Blake2b.BYTES_MAX}`
    );
    if (key) {
      assert(
        key.length >= Blake2b.KEYBYTES_MIN,
        `actual key length ${key.length}, min ${Blake2b.KEYBYTES_MIN}`
      );
      assert(
        key.length <= Blake2b.KEYBYTES_MAX,
        `actual key length ${key.length}, max ${Blake2b.KEYBYTES_MAX}`
      );
    }
    if (salt) {
      assert(
        salt.length === Blake2b.SALTBYTES,
        `actual salt length ${salt.length}, expected ${Blake2b.SALTBYTES}`
      );
    }
    if (personal) {
      assert(
        personal.length === Blake2b.PERSONALBYTES,
        `actual personal length ${personal.length}, ` +
          `expected ${Blake2b.PERSONALBYTES}`
      );
    }
    this.bytes = bytes;
    this.parameterBlock[0] = bytes;
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
      this.h[i] = Blake2b.IV32[i] ^ Blake2b.GET32(this.parameterBlock, i * 4);
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
      input.length >= Blake2b.INPUTBYTES_MIN,
      `input length must be greater than or equal to ${Blake2b.INPUTBYTES_MIN}`
    );
    assert(
      input.length <= Blake2b.INPUTBYTES_MAX,
      `input length must be less than or equal to ${Blake2b.INPUTBYTES_MAX}`
    );
    this.blake2bUpdate(input);
    return input.length;
  }

  public async read(out: Uint8Array): Promise<Deno.ReadResult> {
    assert(
      out.length >= this.bytes,
      `out length must be greater than or equal to ${this.bytes}`
    );
    this.blake2bFinal(out);
    return { eof: true, nread: out.length };
  }

  // Little-endian byte access
  protected static GET32(arr: Uint8Array, i: number): number {
    return arr[i] ^ (arr[i + 1] << 8) ^ (arr[i + 2] << 16) ^ (arr[i + 3] << 24);
  }

  // 64-bit unsigned addition
  // Sets v[a,a+1] += v[b,b+1]
  protected static ADD64AA(v: Uint32Array, a: number, b: number): void {
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
  protected static ADD64AC(
    v: Uint32Array,
    a: number,
    b0: number,
    b1: number
  ): void {
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
  private GMIX(
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
    // v[a,a+1] += v[b,b+1] ... in JS we must store a uint64 as two uint32s
    Blake2b.ADD64AA(this.v, a, b);
    // v[a, a+1] += x ... x0 is the low 32 bits of x, x1 is the high 32 bits
    Blake2b.ADD64AC(this.v, a, x0, x1);
    // v[d,d+1] = (v[d,d+1] xor v[a,a+1]) rotated to the right by 32 bits
    let xor0: number = this.v[d] ^ this.v[a];
    let xor1: number = this.v[d + 1] ^ this.v[a + 1];
    this.v[d] = xor1;
    this.v[d + 1] = xor0;
    Blake2b.ADD64AA(this.v, c, d);
    // v[b,b+1] = (v[b,b+1] xor v[c,c+1]) rotated right by 24 bits
    xor0 = this.v[b] ^ this.v[c];
    xor1 = this.v[b + 1] ^ this.v[c + 1];
    this.v[b] = (xor0 >>> 24) ^ (xor1 << 8);
    this.v[b + 1] = (xor1 >>> 24) ^ (xor0 << 8);
    Blake2b.ADD64AA(this.v, a, b);
    Blake2b.ADD64AC(this.v, a, y0, y1);
    // v[d,d+1] = (v[d,d+1] xor v[a,a+1]) rotated right by 16 bits
    xor0 = this.v[d] ^ this.v[a];
    xor1 = this.v[d + 1] ^ this.v[a + 1];
    this.v[d] = (xor0 >>> 16) ^ (xor1 << 16);
    this.v[d + 1] = (xor1 >>> 16) ^ (xor0 << 16);
    Blake2b.ADD64AA(this.v, c, d);
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
      this.m[i] = Blake2b.GET32(this.b, 4 * i);
    }
    // twelve rounds of mixing
    for (i = 0; i < 12; i++) {
      this.GMIX(
        0,
        8,
        16,
        24,
        Blake2b.SIGMA82[i * 16 + 0],
        Blake2b.SIGMA82[i * 16 + 1]
      );
      this.GMIX(
        2,
        10,
        18,
        26,
        Blake2b.SIGMA82[i * 16 + 2],
        Blake2b.SIGMA82[i * 16 + 3]
      );
      this.GMIX(
        4,
        12,
        20,
        28,
        Blake2b.SIGMA82[i * 16 + 4],
        Blake2b.SIGMA82[i * 16 + 5]
      );
      this.GMIX(
        6,
        14,
        22,
        30,
        Blake2b.SIGMA82[i * 16 + 6],
        Blake2b.SIGMA82[i * 16 + 7]
      );
      this.GMIX(
        0,
        10,
        20,
        30,
        Blake2b.SIGMA82[i * 16 + 8],
        Blake2b.SIGMA82[i * 16 + 9]
      );
      this.GMIX(
        2,
        12,
        22,
        24,
        Blake2b.SIGMA82[i * 16 + 10],
        Blake2b.SIGMA82[i * 16 + 11]
      );
      this.GMIX(
        4,
        14,
        16,
        26,
        Blake2b.SIGMA82[i * 16 + 12],
        Blake2b.SIGMA82[i * 16 + 13]
      );
      this.GMIX(
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
  private blake2bFinal(out: Uint8Array): void {
    this.t += this.c; // mark last block offset
    while (this.c < 128) {
      // fill up with zeros
      this.b[this.c++] = 0;
    }
    this.blake2bCompress(true); // final block flag = 1
    for (let i: number = 0; i < this.bytes; i++) {
      out[i] = this.h[i >> 2] >> (8 * (i & 3));
    }
  }
}
