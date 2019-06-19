import { test, runIfMain } from "https://deno.land/x/testing/mod.ts";
import {
  assertEquals,
  assertThrows
} from "https://deno.land/x/testing/asserts.ts";
import {
  BYTES_MAX,
  KEYBYTES_MAX,
  SALTBYTES,
  PERSONALBYTES,
  Blake2b,
  blake2b
} from "./mod.ts";
import { TestVector, parseTestVector } from "./test_util.ts";

const testVectors: TestVector[] = JSON.parse(
  new TextDecoder().decode(Deno.readFileSync("./test_vectors.json"))
).map(parseTestVector);

testVectors.forEach(
  (
    { expectedLength, expected, input, key, salt, personal }: TestVector,
    i: number
  ): void => {
    test({
      name: `vector ${i}`,
      fn(): void {
        const hash: any = blake2b(
          input,
          null,
          null,
          expectedLength,
          key,
          salt,
          personal
        );
        assertEquals(hash, expected);
      }
    });
  }
);

test({
  name: "throws on invalid digest length",
  fn(): void {
    assertThrows(() => new Blake2b(0));
  }
});

test({
  name: "throws on invalid key length",
  fn(): void {
    assertThrows(
      () => new Blake2b(BYTES_MAX, new Uint8Array(KEYBYTES_MAX + 1))
    );
  }
});

test({
  name: "throws on invalid salt length",
  fn(): void {
    assertThrows(
      () =>
        new Blake2b(
          BYTES_MAX,
          new Uint8Array(KEYBYTES_MAX),
          new Uint8Array(SALTBYTES + 1)
        )
    );
  }
});

test({
  name: "throws on invalid personal length",
  fn(): void {
    assertThrows(
      () =>
        new Blake2b(
          BYTES_MAX,
          new Uint8Array(KEYBYTES_MAX),
          new Uint8Array(SALTBYTES),
          new Uint8Array(PERSONALBYTES + 1)
        )
    );
  }
});

test({
  name: "passes RFC examples",
  async fn(): Promise<void> {
    let hash: any = blake2b("abc", "utf8", "hex", BYTES_MAX);

    assertEquals(
      hash,
      "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1" +
        "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
    );

    hash = blake2b("", "utf8", "hex", BYTES_MAX);
    assertEquals(
      hash,
      "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419" +
        "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    );

    hash = blake2b(
      "The quick brown fox jumps over the lazy dog",
      "utf8",
      "hex",
      BYTES_MAX
    );
    assertEquals(
      hash,
      "a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673" +
        "f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918"
    );
  }
});

test({
  name: "allows multiple updates",
  async fn(): Promise<void> {
    const b: Blake2b = new Blake2b(32);

    for (let i: number = 0; i < 10; i++) {
      b.update("Hej, Verden", "utf8");
    }

    const hash: any = b.digest("hex");

    assertEquals(
      hash,
      "cbc20f347f5dfe37dc13231cbf7eaa4ec48e585ec055a96839b213f62bd8ce00"
    );
  }
});

test({
  name: "allows unsafe short digest",
  async fn(): Promise<void> {
    const b: Blake2b = new Blake2b(16);

    for (let i: number = 0; i < 10; i++) {
      b.update("Hej, Verden", "utf8");
    }

    const hash: any = b.digest("hex");

    assertEquals(hash, "decacdcc3c61948c79d9f8dee5b6aa99");
  }
});

test({
  name: "allows macin with key",
  async fn(): Promise<void> {
    const key: Uint8Array = new Uint8Array(32).fill(108);

    for (let i = 1; i < key.length; i += 2) {
      key[i] = 111;
    }

    const b: Blake2b = new Blake2b(32, key);

    for (let i: number = 0; i < 10; i++) {
      b.update("Hej, Verden", "utf8");
    }

    const hash: any = b.digest("hex");

    assertEquals(
      hash,
      "405f14acbeeb30396b8030f78e6a84bab0acf08cb1376aa200a500f669f675dc"
    );
  }
});

test({
  name: "allows macin with key and short digest",
  async fn(): Promise<void> {
    const key: Uint8Array = new Uint8Array(32).fill(108);

    for (let i = 1; i < key.length; i += 2) {
      key[i] = 111;
    }

    const b: Blake2b = new Blake2b(16, key);

    for (let i: number = 0; i < 10; i++) {
      b.update("Hej, Verden", "utf8");
    }

    const hash: any = b.digest("hex");

    assertEquals(hash, "fb43f0ab6872cbfd39ec4f8a1bc6fb37");
  }
});

runIfMain(import.meta, { parallel: true });
