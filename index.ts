import { assert } from "https://deno.land/x/testing/asserts.ts";
import { Wasm, loadWasm } from "./loadWasm.ts";

export class Blake2b implements Deno.Reader, Deno.Writer {
  protected static wasm: Wasm = loadWasm();
  protected static freeList: number[] = [];
  protected static head: number = 64;
  public static readonly BYTES_MIN: number = 1;
  public static readonly BYTES_MAX: number = 64;
  public static readonly INPUTBYTES_MIN: number = 0;
  public static readonly INPUTBYTES_MAX: bigint = 2n ** 128n - 1n;
  public static readonly KEYBYTES_MIN: number = 0;
  public static readonly KEYBYTES_MAX: number = 64;
  public static readonly SALTBYTES: number = 16;
  public static readonly PERSONALBYTES: number = 16;
  public static readonly WASM: Uint8Array = Blake2b.wasm.buffer;

  private finalized: boolean;
  private pointer: number;
  public readonly bytes: number;

  public constructor(
    bytes: number,
    key?: Uint8Array,
    salt?: Uint8Array,
    personal?: Uint8Array
  ) {
    assert(bytes >= Blake2b.BYTES_MIN);
    assert(bytes <= Blake2b.BYTES_MAX);
    if (salt) {
      assert(salt.length === Blake2b.SALTBYTES);
    }
    if (personal) {
      assert(personal.length === Blake2b.PERSONALBYTES);
    }
    if (key) {
      assert(key.length >= Blake2b.KEYBYTES_MIN);
      assert(key.length <= Blake2b.KEYBYTES_MAX);
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
      Blake2b.wasm.memory.set(salt, 32);
    }
    if (personal) {
      Blake2b.wasm.memory.set(personal, 48);
    }

    if (this.pointer + 216 > Blake2b.wasm.memory.length) {
      Blake2b.wasm.realloc(this.pointer + 216); // we need 216 state bytes
    }

    Blake2b.wasm.exports.blake2b_init(this.pointer, this.bytes);

    if (key) {
      this.update(key);
      Blake2b.wasm.memory.fill(0, Blake2b.head, Blake2b.head + key.length);
      Blake2b.wasm.memory[this.pointer + 200] = 128;
    }
  }

  private update(input: Uint8Array): void {
    if (Blake2b.head + input.length > Blake2b.wasm.memory.length) {
      Blake2b.wasm.realloc(Blake2b.head + input.length);
    }
    Blake2b.wasm.memory.set(input, Blake2b.head);
    Blake2b.wasm.exports.blake2b_update(
      this.pointer,
      Blake2b.head,
      Blake2b.head + input.length
    );
  }

  private digest(out: Uint8Array): void {
    this.finalized = true;
    Blake2b.freeList.push(this.pointer);
    Blake2b.wasm.exports.blake2b_final(this.pointer);
    for (var i = 0; i < this.bytes; i++) {
      out[i] = Blake2b.wasm.memory[this.pointer + 128 + i];
    }
  }

  public async write(input: Uint8Array): Promise<number> {
    assert(input.length >= Blake2b.INPUTBYTES_MIN);
    assert(input.length <= Blake2b.INPUTBYTES_MAX);
    assert(!this.finalized);
    this.update(input);
    return input.length;
  }

  public async read(out: Uint8Array): Promise<Deno.ReadResult> {
    assert(out.length >= this.bytes);
    assert(!this.finalized);
    this.digest(out);
    return { eof: true, nread: this.bytes };
  }
}
