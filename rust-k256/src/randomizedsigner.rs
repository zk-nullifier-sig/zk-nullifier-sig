use super::{
    CryptoRngCore, NonZeroScalar, PlumeSignature, PlumeSignatureV1Fields, ProjectivePoint,
    SecretKey, PlumeMessage
};
use k256::{
    elliptic_curve::{
        hash2curve::{ExpandMsgXmd, GroupDigest},
        point::NonIdentity,
        sec1::ToEncodedPoint,
    },
    sha2::{Digest, Sha256},
    Secp256k1,
};
// Removed `pub` from this, since it's only interested to those who already imported `signature`
use signature::{Error, RandomizedSigner};

/// `PlumeSigner` is a `struct` that contains a reference to a secret key and a
/// boolean defining output [`PlumeSignature`] variant.
///
/// It implements the `RandomizedSigner` trait to generate signatures using the provided secret
/// key. The struct is generic over the lifetime of the secret key reference so that the key can be borrowed immutably.
///
/// `serde` traits aren't added to this struct on purpose. It's a wrapper around [`SecretKey`] which provides variety of serialization formats (SEC1, bytes, ...).
/// Also it uses just a reference to the secret key itself, so the choices for handling the key is kept open here.
pub struct PlumeSigner<'signing> {
    /// The secret key to use for signing. This is borrowed immutably.
    secret_key: &'signing SecretKey,
    pub dst: &'signing [u8],
    /// Whether to generate a PlumeSignature V1 (true) or PlumeSignature V2 (false).
    ///
    /// `bool` is fine to use here since the choice affects only the hashing which doesn't
    /// involve the key material, and distinguishing on it doesn't look possible
    // Since #lastoponsecret seems to me indistinguishible between variants here's `bool` is used instead of `subtle`
    pub v1: bool,
}
impl<'signing> PlumeSigner<'signing> {
    /// Creates a new `PlumeSigner` instance with the given secret key and signature
    /// variant.
    pub fn new(secret_key: &'signing SecretKey, dst: &'signing [u8], v1: bool) -> PlumeSigner<'signing> {
        PlumeSigner { secret_key, dst, v1 }
    }
}
impl<'signing> RandomizedSigner<PlumeSignature> for PlumeSigner<'signing> {
    fn try_sign_with_rng(
        &self,
        rng: &mut impl CryptoRngCore,
        msg: &[u8],
    ) -> Result<PlumeSignature, Error> {
        // Pick a random r from Fp
        let r_scalar = SecretKey::random(rng);

        let r_point = r_scalar.public_key();

        let pk = self.secret_key.public_key();
        let pk_bytes = pk.to_encoded_point(true).to_bytes();

        // Compute h = htc([m, pk])
        let hashed_to_curve = NonIdentity::new(
            Secp256k1::hash_from_bytes::<ExpandMsgXmd<Sha256>>(
                &[msg, &pk_bytes], &[self.dst]
            ).map_err(|_| Error::new())?,
        )
        .expect("something is drammatically wrong if the input hashed to the identity");

        // it feels not that scary to store `r_scalar` as `NonZeroScalar` (compared to `self.secret_key`)
        let r_scalar = r_scalar.to_nonzero_scalar();

        // Compute z = h^r
        let hashed_to_curve_r = hashed_to_curve * r_scalar;

        // Compute nul = h^sk
        let nullifier = hashed_to_curve * self.secret_key.to_nonzero_scalar();

        // Compute c = sha512([g, pk, h, nul, g^r, z])
        let mut hasher = Sha256::new();
        // shorthand for updating the hasher which repeats a lot below
        macro_rules! updhash {
            ($p:ident) => {
                hasher.update($p.to_encoded_point(true).as_bytes())
            };
        }
        if self.v1 {
            hasher.update(ProjectivePoint::GENERATOR.to_encoded_point(true).as_bytes());
            hasher.update(pk_bytes);
            updhash!(hashed_to_curve);
        }
        updhash!(nullifier);
        updhash!(r_point);
        updhash!(hashed_to_curve_r);

        let c = hasher.finalize();
        let c_scalar = NonZeroScalar::from_repr(c)
            .expect("it should be impossible to get the hash equal to zero");

        // Compute $s = r + sk ⋅ c$. #lastoponsecret
        let s_scalar = NonZeroScalar::new(*r_scalar + *(c_scalar * self.secret_key.to_nonzero_scalar()))
            .expect("something is terribly wrong if the nonce is equal to negated product of the secret and the hash");

        Ok(PlumeSignature {
            message: PlumeMessage{ dst: self.dst.to_owned(), msg: msg.to_owned() },
            pk: pk.into(),
            nullifier: nullifier.to_point().to_affine(),
            c: c_scalar,
            s: s_scalar,
            v1specific: if self.v1 {
                Some(PlumeSignatureV1Fields {
                    r_point: r_point.into(),
                    hashed_to_curve_r: hashed_to_curve_r.to_point().to_affine(),
                })
            } else {
                None
            },
        })
    }
}
