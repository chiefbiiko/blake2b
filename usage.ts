import { Blake2b } from "https://deno.land/x/blake2b/mod.ts";
import { toHexString } from "./util.ts";

const encoder: TextEncoder = new TextEncoder();
const msg: Uint8Array = encoder.encode("food");
const key: Uint8Array = encoder.encode("sesameopendagatesaucepastacheese");

async function main(): Promise<void> {
  // hash example
  let b: Blake2b = new Blake2b(Blake2b.DIGESTBYTES_MAX);
  const hash: Uint8Array = new Uint8Array(b.digestBytes);
  await b.write(msg); // call write as often you like
  await b.read(hash);
  console.log(`BLAKE2b512 of msg ${msg}: ${toHexString(hash)}`);
  // mac example
  b = new Blake2b(Blake2b.DIGESTBYTES_MAX, key);
  const mac: Uint8Array = new Uint8Array(b.digestBytes);
  await b.write(msg);
  await b.read(mac);
  console.log(`BLAKE2b512 of msg ${msg}, key ${key}: ${toHexString(mac)}`);
}

main();
