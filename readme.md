# blake2b

[![Travis](http://img.shields.io/travis/chiefbiiko/blake2b.svg?style=flat)](http://travis-ci.org/chiefbiiko/blake2b) [![AppVeyor](https://ci.appveyor.com/api/projects/status/github/chiefbiiko/blake2b?branch=master&svg=true)](https://ci.appveyor.com/project/chiefbiiko/blake2b)

---

BLAKE2b implemented in WebAssembly.

> Tailored to `Deno`. Catch up if you ain't with da wave yet!

All credit to the original authors Jean-Philippe Aumasson, Samuel Neves, Zooko Wilcox-O'Hearn, and Christian Winnerlein, as well as open-source contributors [dcposch](https://github.com/dcposch/blakejs), [mafintosh](https://github.com/mafintosh/blake2b-wasm),
and [emilbayes](https://github.com/emilbayes/blake2b) for porting the reference
implementation to JavaScript and WebAssembly.

---

## Import

```ts
import { Blake2b }  from "https://deno.land/x/blake2b/mod.ts";
```

---

## Usage

```ts
import { Blake2b } from "https://deno.land/x/blake2b/mod.ts";
import { toHexString } from "https://deno.land/x/blake2b/test_util.ts";

const encoder: TextEncoder = new TextEncoder();
const msg: Uint8Array = encoder.encode("food");
const key: Uint8Array = encoder.encode("sesameopendagatesaucepastacheese");

async function main() {
  console.log("hash example");
  let b: Blake2b = new Blake2b(Blake2b.BYTES_MAX);
  const hash: Uint8Array = new Uint8Array(b.bytes);
  await b.write(msg); // call write as often you like
  await b.read(hash);
  console.log(`BLAKE2b512 of msg ${msg}: ${toHexString(hash)}`);
  console.log("mac example");
  b = new Blake2b(Blake2b.BYTES_MAX, key);
  const mac: Uint8Array = new Uint8Array(b.bytes);
  await b.write(msg);
  await b.read(mac);
  console.log(`BLAKE2b512 of msg ${msg}, key ${key}: ${toHexString(mac)}`);
}

main();
```

---

## API

Class `Blake2b` implements `Deno.Reader` and `Deno.Writer`. To update the `Blake2b` instance call `Blake2b.prototype.write` as often you like, `Blake2b.prototype.read` once to digest and obtain the hash. 

#### `new Blake2b(bytes: number, key?: Uint8Array, salt?: Uint8Array, personal?: Uint8Array)`

Create a `Blake2b` instance. `bytes` must indicate the desired digest length. If in doubt about your digest length requirements, just fall back to `Blake2b.BYTES_MAX`, which yields a 64-byte digest. If `key` is given the digest is essentially a MAC. The `key` length can be any integer in `0..64`. Again, if in doubt about your `key` length requirements, settle for a paranoid `64` which is `Blake2b.KEYBYTES_MAX` and sleep tight. `salt` and `personal` must both have length `16` if set. They can be used for salting and defining unique hash functions for multiple applications respectively.

#### `Blake2b.prototype.write(input: Uint8Array): Promise<number>`

Update a `Blake2b` instance. Can be called multiple times.

#### `Blake2b.prototype.read(out: Uint8Array): Promise<deno.ReadResult>`

Obtain a hash digest. `out.length` must not be less than parameter `bytes` at instantiation.

#### `<Blake2b>.bytes: number`

A `readonly` instance property indicating the digest length defined at instantiation.

There are a couple handy static constants you should be aware of:

``` ts
Blake2b.BYTES_MIN // 1
Blake2b.BYTES_MAX // 64
Blake2b.INPUTBYTES_MIN  // 0
Blake2b.INPUTBYTES_MAX  // 2n ** 128n - 1n
Blake2b.KEYBYTES_MIN    // 0
Blake2b.KEYBYTES_MAX    // 64
Blake2b.SALTBYTES       // 16
Blake2b.PERSONALBYTES   // 16
Blake2b.WASM // WebAssembly module (not so handy)
```

---

## Readables

[Saarinen, M-J; Aumasson, J-P (November 2015). The BLAKE2 Cryptographic Hash and Message Authentication Code (MAC). IETF. doi:10.17487/RFC7693. RFC 7693.](https://tools.ietf.org/html/rfc7693)

[Aumasson, Neves, Wilcox-O’Hearn, and Winnerlein (January 2013). "BLAKE2: simpler, smaller, fast as MD5".](https://blake2.net/blake2.pdf)

---

## License

[MIT](./license.md)