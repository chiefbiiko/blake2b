import { test, runIfMain } from "https://deno.land/x/testing/mod.ts";
import {
  assertEquals,
  assertThrows,
  assertThrowsAsync
} from "https://deno.land/x/testing/asserts.ts";

import { Blake2b } from "./mod.ts";
import { toUint8Array, parseTestData, toHexString } from "./util.ts";

const testVectors = JSON.parse(
  new TextDecoder().decode(Deno.readFileSync("./test_vectors.json"))
);

test(function throwsOnInvalidDigestLength() {
  assertThrows(() => new Blake2b(0));
});

test(function throwsOnInvalidKeyLength() {
  assertThrows(
    () =>
      new Blake2b(
        Blake2b.DIGESTBYTES_MAX,
        new Uint8Array(Blake2b.KEYBYTES_MAX + 1)
      )
  );
});

test(function throwsOnInvalidSaltLength() {
  assertThrows(
    () =>
      new Blake2b(
        Blake2b.DIGESTBYTES_MAX,
        new Uint8Array(Blake2b.KEYBYTES_MAX),
        new Uint8Array(Blake2b.SALTBYTES + 1)
      )
  );
});

test(function throwsOnInvalidPersonalLength() {
  assertThrows(
    () =>
      new Blake2b(
        Blake2b.DIGESTBYTES_MAX,
        new Uint8Array(Blake2b.KEYBYTES_MAX),
        new Uint8Array(Blake2b.SALTBYTES),
        new Uint8Array(Blake2b.PERSONALBYTES + 1)
      )
  );
});

test(async function throwsOnInvalidInputLength() {
  assertThrowsAsync(async () => {
    const b: Blake2b = new Blake2b(Blake2b.DIGESTBYTES_MAX);
    await b.write(new Uint8Array(Blake2b.INPUTBYTES_MAX + 1));
  });
});

test(function passesTestVectors() {
  testVectors
    .map(parseTestData)
    .forEach(async ({ outlen, input, key, salt, personal, expected }) => {
      const b: Blake2b = new Blake2b(outlen, key, salt, personal);
      const out: Uint8Array = new Uint8Array(outlen);
      await b.write(input);
      await b.read(out);
      assertEquals(out, expected);
    });
});

test(async function passesRFCExamples() {
  const digestLength: number = Blake2b.DIGESTBYTES_MAX;
  let b: Blake2b = new Blake2b(digestLength);
  const out: Uint8Array = new Uint8Array(digestLength);
  await b.write(toUint8Array("abc"));
  await b.read(out);
  assertEquals(
    toHexString(out),
    "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1" +
      "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
  );
  b = new Blake2b(digestLength);
  out.fill(0);
  await b.write(toUint8Array(""));
  await b.read(out);
  assertEquals(
    toHexString(out),
    "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419" +
      "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
  );
  b = new Blake2b(digestLength);
  out.fill(0);
  await b.write(toUint8Array("The quick brown fox jumps over the lazy dog"));
  await b.read(out);
  assertEquals(
    toHexString(out),
    "a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673" +
      "f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918"
  );
});

test(async function allowsMultipleWrites() {
  const digestLength: number = 32;
  const b: Blake2b = new Blake2b(digestLength);
  const out: Uint8Array = new Uint8Array(digestLength);
  const buf: Uint8Array = toUint8Array("Hej, Verden");
  for (let i: number = 0; i < 10; i++) await b.write(buf);
  await b.read(out);
  assertEquals(
    toHexString(out),
    "cbc20f347f5dfe37dc13231cbf7eaa4ec48e585ec055a96839b213f62bd8ce00"
  );
});

test(async function allowsUnsafeShortDigest() {
  const digestLength: number = 16;
  const b: Blake2b = new Blake2b(digestLength);
  const out: Uint8Array = new Uint8Array(digestLength);
  const buf: Uint8Array = toUint8Array("Hej, Verden");
  for (let i: number = 0; i < 10; i++) await b.write(buf);
  await b.read(out);
  assertEquals(toHexString(out), "decacdcc3c61948c79d9f8dee5b6aa99");
});

test(async function allowsMacinWithKey() {
  const key: Uint8Array = new Uint8Array(32).fill(108);
  for (let i = 1; i < key.length; i += 2) key[i] = 111;
  const digestLength: number = 32;
  const b: Blake2b = new Blake2b(digestLength, key);
  const out: Uint8Array = new Uint8Array(digestLength);
  const buf: Uint8Array = toUint8Array("Hej, Verden");
  for (let i: number = 0; i < 10; i++) await b.write(buf);
  await b.read(out);
  assertEquals(
    toHexString(out),
    "405f14acbeeb30396b8030f78e6a84bab0acf08cb1376aa200a500f669f675dc"
  );
});

test(async function allowsMacinWithKeyAndShortDigest() {
  const key: Uint8Array = new Uint8Array(32).fill(108);
  for (let i = 1; i < key.length; i += 2) key[i] = 111;
  const digestLength: number = 16;
  const b: Blake2b = new Blake2b(digestLength, key);
  const out: Uint8Array = new Uint8Array(digestLength);
  const buf: Uint8Array = toUint8Array("Hej, Verden");
  for (let i: number = 0; i < 10; i++) await b.write(buf);
  await b.read(out);
  assertEquals(toHexString(out), "fb43f0ab6872cbfd39ec4f8a1bc6fb37");
});

runIfMain(import.meta, { parallel: true });
