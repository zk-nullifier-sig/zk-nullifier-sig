import { Point } from '@noble/secp256k1';
import { uint8ArrayToHex } from './encoding.js';

export interface HashedPoint {
  x: {
    toString(): string;
  };
  y: {
    toString(): string;
  };
}

export function multiplyPoint(h: HashedPoint, secretKey: Uint8Array) {
  const hashPoint = new Point(BigInt('0x' + h.x.toString()), BigInt('0x' + h.y.toString()));

  return hashPoint.multiply(BigInt('0x' + uint8ArrayToHex(secretKey)));
}
