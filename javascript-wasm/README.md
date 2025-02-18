This is wrapper around `plume_rustcrypto` crate to produce PLUME signatures in JS contexts using Wasm.

TODO add here couple of examples from systems which uses this.

# Getting Started

Get the package from NPM. The repository contains Rust code for generating Wasm and packaging it.

The package usage outline; see the details in subsections.
```js
// ...
let result = plume.sign(isV1, secretKeySec1Der, msg);
console.log(result.nullifier);
result.zeroizePrivateParts();
```

Please, refer to the JS-doc for types description, function signatures, and exceptions notes.

Values in the following examples are in line with tests in the wrapped crate.
## producing the signature
```js
import * as plume from 'plume-sig';

let result = plume.sign(
  false, 
  new Uint8Array([48, 107, 2, 1, 1, 4, 32, 81, 155, 66, 61, 113, 95, 139, 88, 31, 79, 168, 238, 89, 244, 119, 26, 91, 68, 200, 19, 11, 78, 62, 172, 202, 84, 165, 109, 218, 114, 180, 100, 161, 68, 3, 66, 0, 4, 12, 236, 2, 142, 224, 141, 9, 224, 38, 114, 166, 131, 16, 129, 67, 84, 249, 234, 191, 255, 13, 230, 218, 204, 28, 211, 167, 116, 73, 96, 118, 174, 239, 244, 113, 251, 160, 64, 152, 151, 182, 164, 142, 136, 1, 173, 18, 249, 93, 0, 9, 183, 83, 207, 143, 81, 193, 40, 191, 107, 11, 210, 127, 189]),
  new Uint8Array([
    65, 110, 32, 101, 120, 97, 109, 112, 108, 101, 32, 97, 112, 112, 32, 109, 101, 115, 115, 97, 103, 101, 32, 115, 116, 114, 105, 110, 103
  ])
);
```
## getters
`PlumeSignature` provide getters for each property of it, so you have access to any of them upon signing.
```js
// ...
console.log(result.nullifier);
/* Uint8Array(33) [
    3,  87, 188,  62, 210, 129, 114, 239,
  138, 221, 228, 185, 224, 194, 204, 231,
   69, 252, 197, 166, 100, 115, 164,  92,
   30,  98, 111,  29,  12, 103, 229,  88,
   48
] */
console.log(result.s);
/* Uint8Array(109) [
   48, 107,   2,   1,   1,   4,  32,  73,  27, 195, 183, 106,
  202, 136, 167,  50, 193, 119, 152, 153, 233,  56, 176,  58,
  221, 183,   4, 126, 189,  69, 201, 173, 102,  98, 248,  36,
  112, 183, 176, 161,  68,   3,  66,   0,   4,  13,  18, 115,
  220, 215, 120, 156,  20, 128, 225, 106,  29, 255,  16, 218,
    5,  19, 179,  80, 204,  25, 144,  61, 150, 121,  83,  76,
  174,  21, 232,  58, 153,  97, 227, 239,  78, 114, 199,  53,
  138,  93, 108, 150,  98, 141,  89, 159, 219, 243, 182, 188,
   22, 224, 154, 171,
  ... 9 more items
] */
console.log(result.c);
console.log(result.pk);
console.log(result.message);
console.log(result.v1specific);
// undefined
```
Note that variant is specified by `v1specific`; if it's `undefined` then the object contains V2, otherwise it's V1.
```js
// ...
if (result.v1specific) {
  console.log(result.v1specific.r_point);
  console.log(result.v1specific.hashed_to_curve_r);
}
```
Also there's #convertion utility provided.
## zeroization
Depending on your context you might want to clear values of the result from Wasm memory after getting the values.
```js
// ...
result.zeroizePrivateParts();
result.zeroizeAll();
```

# #convertion of `s` to `BigInt`
JS most native format for scalar is `BigInt`, but it's not really transportable or secure, so for uniformity of approach `s` in `PlumeSignature` is defined similar to `c`; but if you want to have it as a `BigInt` there's `sec1DerScalarToBigint` helper funtion.

# Working with source files

This package is built with the tech provided by <https://github.com/rustwasm> which contains everything needed to work with it. Also the wrapper crate was initiated with `wasm-pack-template`.

Note that the wrapper crate has `verify` feature which can check the resulting signature.

# License
See <https://github.com/plume-sig/zk-nullifier-sig/blob/main/LICENSE>.