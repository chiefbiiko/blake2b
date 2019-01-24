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

export function parseTestData(vector: {
  [key: string]: any;
}): { [key: string]: Uint8Array } {
  return {
    outlen: vector.outlen,
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
        : hexWrite(new Uint8Array(vector.personal.length / 2), vector.personal),
    expected: hexWrite(new Uint8Array(vector.out.length / 2), vector.out)
  };
}

export function toHexString(buf: Uint8Array): string {
  let str = "";
  for (let i: number = 0; i < buf.length; i++) str += toHex(buf[i]);
  return str;
}

function toHex(n: number): string {
  if (n < 16) {
    return "0" + n.toString(16);
  }
  return n.toString(16);
}

export function toUint8Array(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

export function assert(cond: boolean, msg: string = "Assertion failed"): void {
  if (!cond) {
    throw Error(msg);
  }
}