const utf8Encoder = new TextEncoder();

export function messageToUint8Array(message: string): Uint8Array {
  return utf8Encoder.encode(message);
}

export function hexToUint8Array(hexString: string): Uint8Array {
  // Source: https://stackoverflow.com/questions/38987784/how-to-convert-a-hexadecimal-string-to-uint8array-and-back-in-javascript/50868276#50868276
  return Uint8Array.from(hexString.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16)));
}

export function uint8ArrayToHex(uint8Array: Uint8Array) {
  // Source: https://stackoverflow.com/questions/38987784/how-to-convert-a-hexadecimal-string-to-uint8array-and-back-in-javascript/50868276#50868276
  return uint8Array.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');
}

export function hexToBigInt(hex: string): bigint {
  return BigInt('0x' + hex);
}

export function uint8ArrayToBigInt(buffer: Uint8Array): bigint {
  return hexToBigInt(uint8ArrayToHex(buffer));
}

export function asciitobytes(s: string): number[] {
  const b: number[] = [];

  for (let i = 0; i < s.length; i++) {
    b.push(s.charCodeAt(i));
  }

  return b;
}

export function concatUint8Arrays(arrays: Uint8Array[]) {
  // sum of individual array lengths
  const totalLength = arrays.reduce((acc, value) => acc + value.length, 0);

  const result = new Uint8Array(totalLength);

  if (!arrays.length) {
    return result;
  }

  // for each array - copy it over result
  // next array is copied right after the previous one
  let length = 0;
  for (let array of arrays) {
    result.set(array, length);
    length += array.length;
  }

  return result;
}
