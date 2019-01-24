# blake2b

[![Travis](http://img.shields.io/travis/chiefbiiko/blake2b.svg?style=flat)](http://travis-ci.org/chiefbiiko/blake2b) [![AppVeyor](https://ci.appveyor.com/api/projects/status/github/chiefbiiko/blake2b?branch=master&svg=true)](https://ci.appveyor.com/project/chiefbiiko/blake2b)

---

BLAKE2b `ts` implementation for `deno`.

---

## Import

```ts
import * as blake2b from "https://raw.githubusercontent.com/chiefbiiko/blake2b/master/mod.ts";
```

---

## Usage

[Hash usage example](./usage.ts)

---

## API

### `new Blake2b(digestLength: number, key?: Uint8Array, salt?: Uint8Array, personal?: Uint8Array)`

Create a Blake2b hash instance. If key is given the digest is essentially a MAC.

There are a couple handy constant exports you should be aware of:

```ts
export const DIGESTBYTES_MIN = 1;
export const DIGESTBYTES_MAX = 64;
export const INPUTBYTES_MIN = 0;
export const INPUTBYTES_MAX = 2 ** 128 - 1;
export const KEYBYTES_MIN = 0;
export const KEYBYTES_MAX = 64;
export const SALTBYTES = 16;
export const PERSONALBYTES = 16;
```

---

## License

[MIT](./license.md)