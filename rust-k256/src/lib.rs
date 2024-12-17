// #![feature(generic_const_expr)]
// #![allow(incomplete_features)]

//! A library for generating and verifying PLUME signatures.
//!
//! See <https://blog.aayushg.com/nullifier> for more information.
//!
//! Find the crate to use with `arkworks-rs` crate as `plume_arkworks`.
//
//! # Examples
//! If you want more control or to be more generic on traits `use` [`PlumeSigner`] from [`randomizedsigner`]
//! ```rust
//! use plume_rustcrypto::{PlumeSignature, SecretKey};
//! use rand_core::OsRng;
//! # fn main() {
//! #   let sk = SecretKey::random(&mut OsRng);
//! #       
//!     let sig_v1 = PlumeSignature::sign_v1(
//!         &sk, b"ZK nullifier signature", &mut OsRng
//!     );
//!     assert!(sig_v1.verify());
//!
//!     let sig_v2 = PlumeSignature::sign_v2(
//!         &sk, b"ZK nullifier signature", &mut OsRng
//!     );
//!     assert!(sig_v2.verify());
//! # }
//! ```

use k256::elliptic_curve::bigint::ArrayEncoding;
use k256::elliptic_curve::ops::Reduce;
use k256::sha2::{digest::Output, Digest, Sha256}; // requires 'getrandom' feature
use k256::ProjectivePoint;
use k256::Scalar;
use k256::U256;
use signature::RandomizedSigner;

/// Exports types from the `k256` crate:
///
/// - `NonZeroScalar`: A secret 256-bit scalar value.
/// - `SecretKey`: A secret 256-bit scalar wrapped in a struct.  
/// - `AffinePoint`: A public elliptic curve point.
pub use k256::{AffinePoint, NonZeroScalar, SecretKey};
/// Re-exports the [`CryptoRngCore`] trait from the [`rand_core`] crate.
/// This allows it to be used from the current module.
pub use rand_core::CryptoRngCore;
#[cfg(feature = "serde")]
/// Provides the ability to serialize and deserialize data using the Serde library.
/// The `Serialize` and `Deserialize` traits from the Serde library are re-exported for convenience.
pub use serde::{Deserialize, Serialize};

mod utils;
// not published due to use of `Projective...`; these utils can be found in other crates
use utils::*;

/// Provides the [`RandomizedSigner`] trait implementation over [`PlumeSignature`].
pub mod randomizedsigner;
use randomizedsigner::PlumeSigner;

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PlumeMessage/* Dst */ {
    // /* dst_ */protocol: &'signing [u8],
    // /* dst_ */msg_id: &'signing [u8],
    /// WARNING: MUST contain the protocol id, and *unique* message id for this protocol. Consider safe separation of these ids (it 
    /// could be length of the protocol id, or anything you choose).
    /// 
    /// WARNING: keep length of this field *less than 255* to enjoy better compatibility and smaller constraints number in 
    /// proving circuits.
    pub dst: Vec<u8>,
    pub msg: Vec<u8>
}
impl PlumeMessage {
    /// Yields the signature with `None` for `v1specific`. Same as using [`RandomizedSigner`] with [`PlumeSigner`];
    /// use it when you don't want to `use` PlumeSigner and the trait in your code.
    pub fn sign_v1(&self, secret_key: &SecretKey, rng: &mut impl CryptoRngCore) -> PlumeSignature {
        PlumeSigner::new(secret_key, &self.dst, true).sign_with_rng(rng, &self.msg)
    }
    /// Yields the signature with `Some` for `v1specific`. Same as using [`RandomizedSigner`] with [`PlumeSigner`];
    /// use it when you don't want to `use` PlumeSigner and the trait in your code.
    pub fn sign_v2(&self, secret_key: &SecretKey, rng: &mut impl CryptoRngCore) -> PlumeSignature {
        // PlumeSigner::new(secret_key, false).sign_with_rng(rng, msg)
        PlumeSigner::new(secret_key, &self.dst, false).sign_with_rng(rng, &self.msg)
    }
}

/// Struct holding signature data for a PLUME signature.
///
/// `v1specific` field differintiate whether V1 or V2 protocol will be used.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PlumeSignature {
    /// The message that was signed.
    pub message: PlumeMessage,
    /// The public key used to verify the signature.
    pub pk: AffinePoint,
    /// The nullifier.
    pub nullifier: AffinePoint,
    /// Part of the signature data. SHA-256 interpreted as a scalar.
    pub c: NonZeroScalar,
    /// Part of the signature data, a scalar value.
    pub s: NonZeroScalar,
    /// Optional signature data for variant 1 signatures.
    pub v1specific: Option<PlumeSignatureV1Fields>,
}
/// Nested struct holding additional signature data used in variant 1 of the protocol.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PlumeSignatureV1Fields {
    /// Part of the signature data, a curve point.  
    pub r_point: AffinePoint,
    /// Part of the signature data, a curve point.
    pub hashed_to_curve_r: AffinePoint,
}
impl PlumeSignature {
    /// Verifies a PLUME signature.
    /// Returns `true` if the signature is valid.
    pub fn verify(&self) -> bool {
        // Verifier check in SNARK:
        // g^[r + sk * c] / (g^sk)^c = g^r
        // hash[m, gsk]^[r + sk * c] / (hash[m, pk]^sk)^c = hash[m, pk]^r
        // c = hash2(g, g^sk, hash[m, g^sk], hash[m, pk]^sk, gr, hash[m, pk]^r)

        let c_scalar = *self.c;

        let r_point = (ProjectivePoint::GENERATOR * *self.s) - (self.pk * (c_scalar));

        let hashed_to_curve = hash_to_curve(&self.message, &self.pk.into());
        if hashed_to_curve.is_err() {
            return false;
        }
        let hashed_to_curve = hashed_to_curve.unwrap();

        let hashed_to_curve_r = hashed_to_curve * *self.s - self.nullifier * (c_scalar);

        if let Some(PlumeSignatureV1Fields {
            r_point: sig_r_point,
            hashed_to_curve_r: sig_hashed_to_curve_r,
        }) = self.v1specific
        {
            // Check whether g^r equals g^s * pk^{-c}
            if r_point != sig_r_point {
                return false;
            }

            // Check whether h^r equals h^{r + sk * c} * nullifier^{-c}
            if hashed_to_curve_r != sig_hashed_to_curve_r {
                return false;
            }

            // Check if the given hash matches
            c_scalar
                == Scalar::reduce(U256::from_be_byte_array(c_sha256_vec_signal(vec![
                    &ProjectivePoint::GENERATOR,
                    &self.pk.into(),
                    &hashed_to_curve,
                    &self.nullifier.into(),
                    &r_point,
                    &hashed_to_curve_r,
                ])))
        } else {
            // Check if the given hash matches
            c_scalar
                == Scalar::reduce(U256::from_be_byte_array(c_sha256_vec_signal(vec![
                    &self.nullifier.into(),
                    &r_point,
                    &hashed_to_curve_r,
                ])))
        }
    }
}

fn c_sha256_vec_signal(values: Vec<&ProjectivePoint>) -> Output<Sha256> {
    let preimage_vec = values
        .into_iter()
        .map(encode_pt)
        .collect::<Vec<_>>()
        .concat();
    let mut sha256_hasher = Sha256::new();
    sha256_hasher.update(preimage_vec.as_slice());
    sha256_hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    // Test encode_pt()
    #[test]
    fn test_encode_pt() {
        let g_as_bytes = encode_pt(&ProjectivePoint::GENERATOR);
        assert_eq!(
            hex::encode(g_as_bytes),
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
    }

    /// Convert a 32-byte array to a scalar
    fn byte_array_to_scalar(bytes: &[u8]) -> Scalar {
        // From https://docs.rs/ark-ff/0.3.0/src/ark_ff/fields/mod.rs.html#371-393
        assert!(bytes.len() == 32);
        let mut res = Scalar::from(0u64);
        let window_size = Scalar::from(256u64);
        for byte in bytes.iter() {
            res *= window_size;
            res += Scalar::from(*byte as u64);
        }
        res
    }

    // Test byte_array_to_scalar()
    #[test]
    fn test_byte_array_to_scalar() {
        let scalar = byte_array_to_scalar(&hex!(
            "c6a7fc2c926ddbaf20731a479fb6566f2daa5514baae5223fe3b32edbce83254"
        ));
        assert_eq!(
            hex::encode(scalar.to_bytes()),
            "c6a7fc2c926ddbaf20731a479fb6566f2daa5514baae5223fe3b32edbce83254"
        );
    }
}
