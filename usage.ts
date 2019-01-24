import {
  Blake2b,
  DIGESTBYTES_MAX
} from "https://raw.githubusercontent.com/chiefbiiko/blake2b/master/mod.ts";
import { toHexString } from "./util.ts";

async function main(): Promise<void> {
  const b: Blake2b = new Blake2b(DIGESTBYTES_MAX);
  const out: Uint8Array = new Uint8Array(DIGESTBYTES_MAX);
  await b.write(new TextEncoder().encode("food")); // call write as often you like
  await b.read(out);
  console.log('BLAKE2b512 hash of "food":', toHexString(out));
}

main();
