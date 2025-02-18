import { CURVE, getPublicKey, Point, utils } from "@noble/secp256k1";
import {
  concatUint8Arrays,
  hexToBigInt,
  hexToUint8Array,
  messageToUint8Array,
  uint8ArrayToBigInt,
} from "./utils/encoding.js";
import { HashedPoint, multiplyPoint } from "./utils/curve.js";
import { BarretenbergSync, Fr } from "@aztec/bb.js";
import { hashToCurve } from "@noble/curves/secp256k1";

// PLUME version
export enum PlumeVersion {
  V1 = 1,
  V2 = 2,
}

export function computeHashToCurve(
  message: Uint8Array,
  pk: Uint8Array,
): HashedPoint {
  // Concatenate message and publicKey
  const preimage = new Uint8Array(message.length + pk.length);
  preimage.set(message);
  preimage.set(pk, message.length);
  const point = hashToCurve(preimage);
  const affinePoint = point.toAffine();
  return {
    x: affinePoint.x.toString(),
    y: affinePoint.y.toString(),
  };
}

export function computeC_V2(
  nullifier: Point,
  rPoint: Point,
  hashedToCurveR: Point,
  hasher: any,
) {
  const nullifierBytes = nullifier.toRawBytes(true);
  const preimage = concatUint8Arrays([
    nullifierBytes,
    rPoint.toRawBytes(true),
    hashedToCurveR.toRawBytes(true),
  ]);
  return hasher(preimage);
}

export function computeC_V1(
  pkBytes: Uint8Array,
  hashedToCurve: HashedPoint,
  nullifier: Point,
  rPoint: Point,
  hashedToCurveR: Point,
  hasher: any,
) {
  const nullifierBytes = nullifier.toRawBytes(true);
  const preimage = concatUint8Arrays([
    Point.BASE.toRawBytes(true),
    pkBytes,
    new Point(
      hexToBigInt(hashedToCurve.x.toString()),
      hexToBigInt(hashedToCurve.y.toString()),
    ).toRawBytes(true),
    nullifierBytes,
    rPoint.toRawBytes(true),
    hashedToCurveR.toRawBytes(true),
  ]);
  return hasher(preimage);
}

export function computeNullifer(hashedToCurve: HashedPoint, sk: Uint8Array) {
  return multiplyPoint(hashedToCurve, sk);
}

export function computeRPoint(rScalar: Uint8Array) {
  return Point.fromPrivateKey(rScalar);
}

export function computeHashToCurveR(
  hashedToCurve: HashedPoint,
  rScalar: Uint8Array,
) {
  return multiplyPoint(hashedToCurve, rScalar);
}

export function computeS(rScalar: Uint8Array, sk: Uint8Array, c: string) {
  return (
    (((uint8ArrayToBigInt(sk) * hexToBigInt(c)) % CURVE.n) +
      uint8ArrayToBigInt(rScalar)) %
    CURVE.n
  ).toString(16);
}

/**
 * Computes and returns the Plume and other signals for the prover.
 * @param {string | Uint8Array} message - Message to sign, in either string or UTF-8 array format.
 * @param {string | Uint8Array} sk - ECDSA secret key to sign with.
 * @param {string| Uint8Array} rScalar - Optional seed for randomness.
 * @returns Object containing Plume and other signals - public key, s, c, gPowR, and hashMPKPowR.
 */
export async function computeAllInputs(
  message: string | Uint8Array,
  sk: string | Uint8Array,
  rScalar?: string | Uint8Array,
  version: PlumeVersion = PlumeVersion.V2,
) {
  const bb = await BarretenbergSync.initSingleton();
  const hasher = (nodes: Uint8Array) =>
    bb
      .poseidon2Hash([Fr.fromBuffer(nodes)])
      .toString()
      .slice(2);

  const skBytes = typeof sk === "string" ? hexToUint8Array(sk) : sk;
  const messageBytes =
    typeof message === "string" ? messageToUint8Array(message) : message;
  const pkBytes = getPublicKey(skBytes, true);

  let rScalarBytes: Uint8Array;
  if (rScalar) {
    rScalarBytes =
      typeof rScalar === "string" ? hexToUint8Array(rScalar) : rScalar;
  } else {
    rScalarBytes = utils.randomPrivateKey();
  }

  const hashedToCurve = computeHashToCurve(messageBytes, pkBytes);
  const nullifier = computeNullifer(hashedToCurve, skBytes);
  const hashedToCurveR = computeHashToCurveR(hashedToCurve, rScalarBytes);
  const rPoint = computeRPoint(rScalarBytes);

  const c =
    version == PlumeVersion.V1
      ? computeC_V1(
          pkBytes,
          hashedToCurve,
          nullifier,
          rPoint,
          hashedToCurveR,
          hasher,
        )
      : computeC_V2(nullifier, rPoint, hashedToCurveR, hasher);
  const s = computeS(rScalarBytes, skBytes, c);

  return {
    nullifier,
    s,
    pk: pkBytes,
    c,
    rPoint,
    hashedToCurveR,
  };
}
