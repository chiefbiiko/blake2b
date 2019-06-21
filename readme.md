# blake2b

[![Travis](http://img.shields.io/travis/chiefbiiko/blake2b.svg?style=flat)](http://travis-ci.org/chiefbiiko/blake2b) [![AppVeyor](https://ci.appveyor.com/api/projects/status/github/chiefbiiko/blake2b?branch=master&svg=true)](https://ci.appveyor.com/project/chiefbiiko/blake2b)

---

BLAKE2b implemented in WebAssembly.

All credit to the original authors Jean-Philippe Aumasson, Samuel Neves, Zooko Wilcox-O'Hearn, and Christian Winnerlein, as well as open-source contributors [dcposch](https://github.com/dcposch/blakejs), [mafintosh](https://github.com/mafintosh/blake2b-wasm),
and [emilbayes](https://github.com/emilbayes/blake2b) for porting the reference
implementation to JavaScript and WebAssembly.

---

## Usage

```ts
import { blake2b } from "https://deno.land/x/blake2b/mod.ts";

console.log('BLAKE2b512 of msg "food":', blake2b("food", "utf8", "hex"));
```

---

## API

#### `new Blake2b(bytes: number, key?: Uint8Array, salt?: Uint8Array, personal?: Uint8Array)`

Create a `Blake2b` instance. `bytes` must indicate the desired digest length. If in doubt about your digest length requirements, just fall back to `Blake2b.BYTES_MAX`, which yields a 64-byte digest. If `key` is given the digest is essentially a MAC. The `key` length can be any integer in `0..64`. Again, if in doubt about your `key` length requirements, settle for a paranoid `64` which is `Blake2b.KEYBYTES_MAX` and sleep tight. `salt` and `personal` must both have length `16` if set. They can be used for salting and defining unique hash functions for multiple applications respectively.

#### `Blake2b#update(input: string | Uint8Array, inputEncoding?: string): Blake2b`

Update a `Blake2b` instance. Can be called multiple times. `inputEncoding` can be one of `"utf8"`, `"hex"`, or `"base64"`. If the input is string and no `inputEncoding` is provided `utf8`-encoding is assumed.

#### `Blake2b#digest(outputEncoding?: string): string | Uint8Array`

Obtain a hash digest. To get a string digest set `outputEncoding` to any of `"utf8"`, `"hex"`, or `"base64"`.

#### `Blake2b#bytes: number`

A `readonly` instance property indicating the digest length defined at instantiation.

There are a couple handy exported constants you should be aware of:

``` ts
BYTES_MIN // 1
BYTES_MAX // 64
INPUTBYTES_MIN  // 0
INPUTBYTES_MAX  // 2n ** 128n - 1n
KEYBYTES_MIN    // 0
KEYBYTES_MAX    // 64
SALTBYTES       // 16
PERSONALBYTES   // 16
```

---

## Readables

[Saarinen, M-J; Aumasson, J-P (November 2015). The BLAKE2 Cryptographic Hash and Message Authentication Code (MAC). IETF. doi:10.17487/RFC7693. RFC 7693.](https://tools.ietf.org/html/rfc7693)

[Aumasson, Neves, Wilcox-O’Hearn, and Winnerlein (January 2013). "BLAKE2: simpler, smaller, fast as MD5".](https://blake2.net/blake2.pdf)

---

## License

[MIT](./LICENSE)