# PLUME: Verifiably Deterministic Signatures on ECDSA

This repository provides libraries for the construction of deterministic nullifiers on Ethereum keys, [ERC 7524]([https://ethereum-magicians.org/t/erc-7524-plume-signature-in-wallets/15902](https://github.com/ethereum/EIPs/pull/7775)). We call them Privately Linked Unique Message Entities (or PLUMEs). PLUMEs enable zk voting, anonymous proof of solvency, and anonymous message board moderation to be possible with Ethereum keys directly, and so we think it is a critical primitive to push forward blockchain adoption. To understand how this primitive works and the reason for design decisions, we recommend checking out [our blog post](https://blog.aayushg.com/posts/plume).

We hope that wallets integrate the javascript, rust, or C repositories for both software and hardware signature generation, and dapps integrate the zk proof in the circuits/ directory.

## Installation

To install our [npm package](https://www.npmjs.com/package/plume-sig) for JS/TS, do

```
yarn add plume-sig
```

To install our [Cargo package](https://crates.io/crates/plume_rustcrypto) for Rust, do

```
cargo add plume_rustcrypto
```

Docs and usage guides are linked to from the packages.

## Contributions and Grants

If you would like to get a grant to create PLUME applications or improve the library, we have grants available from Ethereum Foundation PSE, Gitcoin Grants, and Aztec Foundation, and would give grants for any PRs to the repository! There are projects ideas both below in the README, as well as bountied every issue in Github has a $50 bounty on it. Feel free to pick one up, and dm us on Twitter/Telegram (@yush_g) for guidance and help, or join the discussion in the public channel in the [PSE Discord](https://discord.gg/pse) for progress updates and community questions! This work was generously funded and supported by 0xPARC, Gitcoin donors, EF PSE, Distributed Lab, and Aztec Labs, and exists only due to the valuable work by contributors to this Github such as yush_g, Oren Yomtov, Richard Liu, Blake M Scurr, Piotr Roslaniec, Vu Voth, Weijie Koh, Vivek Bhupatiraju, Yevhenii Sekhin, Nikita Masych, Sergey Kaunov and José Pedro Sousa, who directly contributed to the code. Thanks to Poseidon Labs for a [V2 proposal](https://www.notion.so/PLUME-Discussion-6f4b7e7cf63e4e33976f6e697bf349ff) and Weiking Chen for his filed issues, and our auditors (0xbok), as well as all of the folks [acknowledged in the research paper](https://aayushg.com/thesis.pdf) and [blog post](https://blog.aayushg.com/posts/plume).

If you'd like to contribute, we offer $50 bounties in Eth/DAI for resolving any of the bugs in our issues! Each of them is quite small. That includes
[#28](https://github.com/plume-sig/zk-nullifier-sig/issues/28), [#24](https://github.com/plume-sig/zk-nullifier-sig/issues/24),
[#14](https://github.com/plume-sig/zk-nullifier-sig/issues/14), and [#13](https://github.com/plume-sig/zk-nullifier-sig/issues/13).

## ZK Implementation

- `circom` - The first implementation, well suited for groth16 backends
- `noir` - Unaudited implementation by [Distributed Lab](https://github.com/distributed-lab) and [Aztec Labs](https://aztec-labs.com/). Defaults to the [Barretenberg](https://github.com/AztecProtocol/aztec-packages/tree/master/barretenberg) proving backend.

## Plain implementations

- `rust-k256`: Rust, using the k256 library
- `rust-arkworks`: Rust, using arkworks
- `javascript (wasm)`: JavaScript via wasm-bindgen
- `typescript`: Native typescript implementation

### Wallet Implementations

- Mina: Uses it for nullifiers in their code [here](https://github.com/o1-labs/o1js/blob/main/src/lib/nullifier.ts) and [here](https://github.com/o1-labs/o1js/blob/main/src/mina-signer/src/nullifier.ts). They use Poseidon for the hash function instead, which makes it slower to generate in hardware wallets, but faster to prove. Their [docs for this scheme are here](https://docs.minaprotocol.com/zkapps/o1js-reference/classes/Nullifier).
- Taho: We have an [open PR](https://github.com/tahowallet/extension/pull/3638) that we are waiting on them to merge!
- Rabby: We have an [open PR](https://github.com/RabbyHub/Rabby/pull/2047) that we are waiting on them to merge!
- Metamask: We have an open PR set ([rpc](https://github.com/MetaMask/eth-json-rpc-middleware/pull/198
), [api](https://github.com/MetaMask/api-specs/pull/120), [core](https://github.com/MetaMask/metamask-extension/pull/17482)) that we are waiting on them to merge! Snaps [dropped support for secret key access](https://github.com/MetaMask/snaps/issues/1665) so a Metamask Snap is no longer a tenable path, although we did have a snap as well.
- Aztec: Noir implementation [finished here](https://github.com/distributed-lab/noir-plume), still pending audit.
- Ledger: This [app](https://github.com/base0010/plume-ledger-app/tree/sswu) compiles and generates PLUME signatures on embedded hardware and works on Ledgers. Test via the [Ledger app builder](https://github.com/LedgerHQ/ledger-app-builder).
- ZK Snap: The "holy grail of private voting", according to Ameen, co-author of the private voting report. Uses PLUME as a [core component of an end-to-end private voting system](https://twitter.com/AeriusLabs/status/1753052458249785836).

### Audits

The circom implementation was audited by [PSE Security](https://github.com/0xbok) for the rust and javascript-wasm implementations, both V1 and V2, as well as for V1 circuits. We expect the halo2 circuits to be runnable on mobile (once we have audited that code circa ~April and put up a recursive proving infrastructure setup).

The Noir implementation is unaudited, but is runnable on mobile using native apps (ex. React Native). It also works on Android Progressive Web Apps, as Androids give us a little bit more of that precious RAM on the browser.

## Usage

You probably want to run the plain versions to calculate the correct inputs. You can then use them to prove using the ZK implementations.

### Typescript

Clone this repository and navigate to the `typescript` directory. Install dependencies:

```bash
npm i # or `pnpm i`, `bun i`, etc
```

The library will be built in `typescript/dist`, you can import it through npm links, [gitpkg](https://gitpkg.vercel.app/), copying it into your `node_modules` (YOLO!)... whatever floats your boat.

You can then use it in your project:

```ts
import { computeAllInputs } from 'plume-sig';

const messageBytes = new Uint8Array([ 104, 101, 108, 108, 111,  32, 110, 111, 105, 114 ]) // bytes for "hello noir"
const privateKey = "signers_private_key;
const { nullifier } = await computeAllInputs(messageBytes, privateKey);
```

### Noir

Once you have your inputs, you can import the `noir` package into your project. Add the dependency to your `Nargo.toml` file:

```toml
plume = { tag = "main", git = "https://github.com/plume-sig/zk-nullifier-sig", directory = "circuits/noir/plume" }
```

You can prove your PLUME nullifier is valid like so:

```nr
let plume = Plume::new(message, scalar_c, scalar_s, pubkey_bg, nullifier);
plume.plume_v2();
```

The Noir PLUME implementation is generic over whatever implements the `BigCurveTrait`. This means all the curves in the [`Noir BigCurve` library](https://github.com/noir-lang/noir_bigcurve/tree/main/src/curves), although we only have tests for `secp256k1`.

So for `secp256k1` you probably want to cast your values to `Secp256k1Fq` BigNum, `Secp256k1` Curve, `Secp256k1Scalar`, etc. For example:

```rust
// use noir_bigcurve::curves::secp256k1::{Secp256k1, Secp256k1Fq, Secp256k1Scalar};

let c_bn = Secp256k1Fq::from_be_bytes(c);
let scalar_c: Secp256k1Scalar = ScalarField::from_bignum(c_bn);
let s_bn = Secp256k1Fq::from_be_bytes(s);
let scalar_s: Secp256k1Scalar = ScalarField::from_bignum(s_bn);
let pubkey_bg = Secp256k1 {
   x: Secp256k1Fq::from_be_bytes(pub_key_x),
   y: Secp256k1Fq::from_be_bytes(pub_key_y),
   is_infinity: false,
};
let nullifier = Secp256k1 {
   x: Secp256k1Fq::from_be_bytes(nullifier_x),
   y: Secp256k1Fq::from_be_bytes(nullifier_y),
   is_infinity: false,
};

```

## Testing

### Circom

Circom uses the great `circom-tester` library by [iden3](https://github.com/iden3/circom_tester). Prepare your testing environment by cloning this repository and navigating to the `javascript/` directory. Then install dependencies:

```bash
pnpm i
```

If you encounter an error `No prebuilt binaries found`, try switching to node `v18.17.0` (using [`n`](https://github.com/tj/n), for example) to work around our dependency's [build issue](https://github.com/WiseLibs/better-sqlite3/issues/1027).

To run your tests, navigate to the `circuits/circom` directory and install the dependencies there:

```bash
pnpm i
```

Run the tests:

```bash
pnpm run flatten-deps && \
pnpm run test
```

Be prepared to wait around 20-40 minutes for the tests to complete.

### Noir

Noir provides its own testing environment. Install [Nargo](https://noir-lang.org/docs/getting_started/noir_installation):

```bash
curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash # installs noirup, the nargo installer
noirup # installs nargo
```

Then navigate to `circuits/noir`, and run tests:

```bash
nargo test
```

Tests should finish in around 30-60 seconds.

## Open Work

We invite contributors to collaborate on this effort. There are great tasks for beginners (the issues), a halo2 intermediate level (circuits), cryptography intermediate level (the v1 improvement to make it v2 compatible below), and on the application layer (building apps that use PLUME).  

- Create a V3
  - Reduce number of arguments to c in V1 via Wei Dai's + [Poseidons](https://www.notion.so/mantanetwork/PLUME-Discussion-6f4b7e7cf63e4e33976f6e697bf349ff?pvs=4) suggestions (potentially just g^sk, h[m, pk], g^r is fine) that are currently used in the V2, and write a proof in the Algebraic Group Model for the change.
- [$500 Bounty] Fix stealthdrop circom MVP, the first anonymous airdrop to any Ethereum keys via PLUMEs -- [repo](https://github.com/stealthdrop/stealthdrop/) and [slides](https://docs.google.com/presentation/d/10ZGJvYpIqpON5O4uDf2pdk-PnT8fEVyPOoRqC3VmFn0/edit).
- [$500 Bounty] Implement ZK voting via PLUMEs, as described in [Poseidons proposal](https://www.notion.so/mantanetwork/PLUME-Discussion-6f4b7e7cf63e4e33976f6e697bf349ff?pvs=4).

## Resources

### Paper

Thesis [most up to date version]: <https://aayushg.com/thesis.pdf>  
Paper [slightly out of date]: <https://eprint.iacr.org/2022/1255>

### Slides

[http://slides.plume.run](https://docs.google.com/presentation/d/1mKtOI4XgKrWBEPpKFAYkRjxZsBomwhy6Cc2Ia87hAnY/edit#slide=id.g13e97fbcd2c_0_76)

### Blog Post

[blog.aayushg.com/nullifier](https://blog.aayushg.com/nullifier)

This describes the construction as well as explains our choices for the various hash/hash-to-curve functions.

### ERC 7524

[Official ERC: erc.plume.run](https://erc.plume.run)

[Discussion](https://ethereum-magicians.org/t/erc-7524-plume-signature-in-wallets/15902/2)

[ERC 7524 Taho Wallet Integration](https://github.com/tahowallet/extension/pull/3638)

### Demo

<https://nullifier.xyz>

### Talk

<https://www.youtube.com/watch?v=6ajBnMdJGoY>

### Circom Proof Data

For the V1,
See [this PR](https://github.com/zk-nullifier-sig/zk-nullifier-sig/pull/7).
6.5 million constraints. Mostly dominated by EC operations, but the hashes are very expensive too.  

sha256 ~1.5M.
hash_to_curve ~0.5M.
a/b^c ~1.5 each (this is the sub circuit for the first 2 verification equations).
the remaining 1.5M is probably dominated by calculating g^s and h^s.

For the V2,
the sha256 is 0 cost in the circuit, but is added to the verification cost. This takes in-circuit constraints down to 5M and adds the sha to the verification.

#### Hash to Curve Circom Code and Explainer

<https://github.com/geometryresearch/secp256k1_hash_to_curve/>
<https://geometry.dev/notebook/Hashing-to-the-secp256k1-Elliptic-Curve>

### Nullifier Calculation Spec

<https://hackmd.io/uZQbMHrVSbOHvoI_HrJJlw>

### Circom Verification Spec

<https://hackmd.io/VsojkopuSMuEA4vkYKSB8g?edit>

### V2 Spec and Discussion

[notion.so/mantanetwork/PLUME-Discussion-6f4b7e7cf63e4e33976f6e697bf349ff](https://www.notion.so/mantanetwork/PLUME-Discussion-6f4b7e7cf63e4e33976f6e697bf349ff?pvs=4)

This includes some discussion on justifications for the V2 signature calculation, as well as concrete ways to use PLUME proofs + Proof of ECDSA to do nullifiers and voting respectively.
