import { BYTES_MAX, blake2b } from "./mod.ts";

  console.log("hash example");
  
  console.log('BLAKE2b512 of msg "food":', blake2b("food", "utf8", "hex"));
  
  console.log("mac example");

  const key: string = "sesameopendagatesaucepastacheese";
  console.log(`BLAKE2b512 of msg "food", key "${key}":`, blake2b("food", "utf8", "hex", BYTES_MAX, key));