`plume-sig`
==============
TypeScript implementation of the ERC-7524 PLUME signature scheme.

A new type of cryptographic signature that would allow for anonymous and unique digital identities on the Ethereum blockchain in a verifiable way.

## Installation
`npm install plume-sig`

## Usage

```ts
import { computeAllInputs, PlumeVersion } from 'plume-sig';

return computeAllInputs(message, secretKey);
```

The function returns the signature w.r.t. to given arguments as the object of the following structure.
### `plume`
`secp256k1` point
### `s`
`secp256k1` scalar hexstring
### `pk`
Public key of the signer; SEC1 encoded.
### `c`
SHA-256 hash. It's value depends on `PlumeVersion` of the signature.
### `rPoint`
`secp256k1` point representing the unique random scalar used for signing. V1 specific.
### `hashedToCurveR`
`secp256k1` point. V1 specific.

## Signature variants
The scheme comes in two variants. V2 is default for this implementation.

### Version 1: Verifier Optimized

In a situation where there is a verifier who must *not* know the signer's `pk`, but the signer must nevertheless prove that they know `secretKey` corresponding to the signature given `message`, a zero-knowledge proof is required.

The following verification function may be described via a circuit as part of a non-interactive zero-knowledge proving system, such as Groth16. To create a proof, the prover supplies the following inputs:

### Version 2: Prover Optimized

Currently, SHA-256 hashing operations are particularly expensive with zk proofs in the browser. In the context of PLUME, the computation of $c$ is a bottleneck for efficient proof times, so one modification suggested by the Poseidon team was to move this hash computation outside the circuit, into the verifier.

Due to SHA-256 being a native precompile on Ethereum, this operation will still be efficient for smart contract verifiers.

## License
MIT