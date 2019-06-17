import { BYTES_MAX, blake2b } from "./mod.ts";
// import { toHexString } from "https://deno.land/x/blake2b/test_util.ts";

// const encoder: TextEncoder = new TextEncoder();
// const msg: Uint8Array = encoder.encode("food");


// async function main() {
  console.log("hash example");
  // let b: Blake2b = new Blake2b(Blake2b.BYTES_MAX);
  // const hash: Uint8Array = new Uint8Array(b.bytes);
  // await b.write(msg); // call write as often you like
  // await b.read(hash);
  console.log('BLAKE2b512 of msg "food":', blake2b("food", "utf8", "hex"));
  console.log("mac example");
  // b = new Blake2b(Blake2b.BYTES_MAX, key);
  // const mac: Uint8Array = new Uint8Array(b.bytes);
  // await b.write(msg);
  // await b.read(mac);
  const key: string = "sesameopendagatesaucepastacheese";
  console.log(`BLAKE2b512 of msg "food", key "${key}":`, blake2b("food", "utf8", "hex", BYTES_MAX, key));
// }

// main();
