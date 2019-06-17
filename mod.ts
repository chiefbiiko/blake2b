import { assert } from "https://deno.land/x/testing/asserts.ts";
import {
  encode,
  decode
} from "https://denopkg.com/chiefbiiko/std-encoding/mod.ts";
import { Wasm, loadWasm } from "./loadWasm.ts";

export const BYTES_MIN: number = 1;
export const BYTES_MAX: number = 64;
export const INPUTBYTES_MIN: number = 0;
export const INPUTBYTES_MAX: bigint = 2n ** 128n - 1n;
export const KEYBYTES_MIN: number = 0;
export const KEYBYTES_MAX: number = 64;
export const SALTBYTES: number = 16;
export const PERSONALBYTES: number = 16;

/**
 * @classdesc Class Blake2b implements BLAKE2b as specified in RFC 7693
 *   https://tools.ietf.org/html/rfc7693 and
 *   "BLAKE2: simpler, smaller, fast as MD5" https://blake2.net/blake2.pdf (the
 *   salting and personalization features are specified in the latter only).
 *   All BLAKE2b computations are carried out in WebAssembly.
 */
export class Blake2b {
  protected static wasm: Wasm = loadWasm();
  protected static freeList: number[] = [];
  protected static head: number = 64;
  public static readonly WASM: Uint8Array = Blake2b.wasm.buffer;

  private finalized: boolean;
  private pointer: number;
  public readonly bytes: number;

  /**
   * Creates a new Blake2b instance computing the BLAKE2b checksum with a custom
   * length. Providing a key turns the hash into a MAC. The key must be between
   *  zero and 64 bytes long. The digest size can be a value between 1 and 64 but
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
    key?: string | Uint8Array,
    salt?: string | Uint8Array,
    personal?: string | Uint8Array,
    inputEncoding?: string
  ) {
    assert(bytes >= BYTES_MIN);
    assert(bytes <= BYTES_MAX);

    if (key) {
      if (typeof key === "string") {
        key = encode(key, inputEncoding) as Uint8Array;
      }
      
      assert(key.byteLength <= KEYBYTES_MAX);
    }

    if (salt) {      
      if (typeof salt === "string") {
        salt = encode(salt, inputEncoding) as Uint8Array;
      }
      
      assert(salt.byteLength === SALTBYTES);
    }

    if (personal) {
      if (typeof personal === "string") {
        personal = encode(personal, inputEncoding) as Uint8Array;
      }
      
      assert(personal.byteLength === PERSONALBYTES);
    }

    if (!Blake2b.freeList.length) {
      Blake2b.freeList.push(Blake2b.head);
      Blake2b.head += 216;
    }

    this.bytes = bytes;
    this.finalized = false;
    this.pointer = Blake2b.freeList.pop();

    Blake2b.wasm.memory.fill(0, 0, 64);
    Blake2b.wasm.memory[0] = this.bytes;
    Blake2b.wasm.memory[1] = key ? key.length : 0;
    Blake2b.wasm.memory[2] = 1; // fanout
    Blake2b.wasm.memory[3] = 1; // depth

    if (salt) {
      Blake2b.wasm.memory.set(salt as Uint8Array, 32);
    }

    if (personal) {
      Blake2b.wasm.memory.set(personal as Uint8Array, 48);
    }

    if (this.pointer + 216 > Blake2b.wasm.memory.byteLength) {
      Blake2b.wasm.realloc(this.pointer + 216); // we need 216 state bytes
    }

    Blake2b.wasm.exports.blake2b_init(this.pointer, this.bytes);

    if (key) {
      this.update(key);
      Blake2b.wasm.memory.fill(0, Blake2b.head, Blake2b.head + key.length);
      Blake2b.wasm.memory[this.pointer + 200] = 128;
    }
  }

  /** Updates the hash with additional data. */
  update(input: string | Uint8Array, inputEncoding?: string): Blake2b {
    if (typeof input === "string") {
      input = encode(input, inputEncoding) as Uint8Array;
    }

    if (Blake2b.head + input.byteLength > Blake2b.wasm.memory.byteLength) {
      Blake2b.wasm.realloc(Blake2b.head + input.byteLength);
    }

    Blake2b.wasm.memory.set(input, Blake2b.head);

    Blake2b.wasm.exports.blake2b_update(
      this.pointer,
      Blake2b.head,
      Blake2b.head + input.byteLength
    );

    return this;
  }

  /** Obtains a digest of all fed-in data. */
  digest(outputEncoding?: string): string | Uint8Array {
    assert(!this.finalized);

    const out: Uint8Array = new Uint8Array(this.bytes);

    Blake2b.freeList.push(this.pointer);

    Blake2b.wasm.exports.blake2b_final(this.pointer);

    this.finalized = true;

    for (let i: number = 0; i < this.bytes; i++) {
      out[i] = Blake2b.wasm.memory[this.pointer + 128 + i];
    }

    return outputEncoding ? decode(out, outputEncoding) : out;
  }

  // /** Updates a Blake2b instance with the given data chunk. This method can be
  //  * called multiple times. The returned Promise is rejected if the input's
  //  * length exceeds Blake2b.INPUTBYTES_MAX or the given instance's state has
  //  * been digested, its read method has been called.
  //  *
  //  *         const b: Blake2b = new Blake2b(Blake2b.BYTES_MAX);
  //  *         await b.write(Uint8Array.from([4, 1, 9]));
  //  */
  // public async write(input: Uint8Array): Promise<number> {
  //   assert(input.length <= Blake2b.INPUTBYTES_MAX);
  //   assert(!this.finalized);
  //   this.update(input);
  //   return input.length;
  // }
  //
  // /** Obtains a BLAKE2b checksum by digesting the instance's current state.
  //  * This method can be called once only. The returned Promise is rejected if
  //  * the output buffer's length is less than the instance's digest length or
  //  * this method has been called on the given instance.
  //  *
  //  *         const b: Blake2b = new Blake2b(Blake2b.BYTES_MAX);
  //  *         await b.write(Uint8Array.from([4, 1, 9]));
  //  *         const hash: Uint8Array = new Uint8Array(b.bytes);
  //  *         await b.read(hash);
  //  */
  // public async read(out: Uint8Array): Promise<Deno.ReadResult> {
  //   assert(out.length >= this.bytes);
  //   assert(!this.finalized);
  //   this.digest(out);
  //   return { eof: true, nread: this.bytes };
  // }
}

/**
 * Convenience function for hashing of singular data. If any multiple of msg, 
 * key, salt or personal are passed as strings they must have the same encoding.
 */
export function blake2b(
  msg: string | Uint8Array,
  inputEncoding?: string,
  outputEncoding?: string,
  bytes: number = BYTES_MAX,
  key?: string | Uint8Array,
  salt?: string | Uint8Array,
  personal?: string | Uint8Array
): string | Uint8Array {
  return new Blake2b(bytes, key, salt, personal)
    .update(msg, inputEncoding)
    .digest(outputEncoding);
}
