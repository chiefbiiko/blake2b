export interface TestVector {
  expectedLength: number;
  expected: Uint8Array;
  input: Uint8Array;
  key: Uint8Array;
  salt: Uint8Array;
  personal: Uint8Array;
}

function hexWrite(buf: Uint8Array, hexStr: string): Uint8Array {
  const strLen: number = hexStr.length;
  if (strLen % 2 !== 0) throw new TypeError("Invalid hex string");
  for (let i: number = 0; i < strLen / 2; ++i) {
    const parsed = parseInt(hexStr.substr(i * 2, 2), 16);
    if (Number.isNaN(parsed)) throw new Error("Invalid byte");
    buf[i] = parsed;
  }
  return buf;
}

export function parseTestVector(vector: {
  [key: string]: any;
}): { [key: string]: Uint8Array } {
  return {
    expectedLength: vector.outlen,
    expected: hexWrite(new Uint8Array(vector.out.length / 2), vector.out),
    input: hexWrite(new Uint8Array(vector.input.length / 2), vector.input),
    key:
      vector.key.length === 0
        ? null
        : hexWrite(new Uint8Array(vector.key.length / 2), vector.key),
    salt:
      vector.salt.length === 0
        ? null
        : hexWrite(new Uint8Array(vector.salt.length / 2), vector.salt),
    personal:
      vector.personal.length === 0
        ? null
        : hexWrite(new Uint8Array(vector.personal.length / 2), vector.personal)
  };
}
