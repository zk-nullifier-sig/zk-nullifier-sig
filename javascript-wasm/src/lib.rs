//! sadly `wasm-bindgen` doesn't support top-level @module docs yet

use wasm_bindgen::prelude::*;

#[cfg(feature = "verify")]
use elliptic_curve::sec1::FromEncodedPoint;
use elliptic_curve::sec1::ToEncodedPoint;
use signature::RandomizedSigner;
#[cfg(feature = "verify")]
use std::convert::TryInto;
use zeroize::Zeroize;

#[wasm_bindgen(getter_with_clone)]
/// @typedef {Object} PlumeSignature - Wrapper around [`plume_rustcrypto::PlumeSignature`](https://docs.rs/plume_rustcrypto/latest/plume_rustcrypto/struct.PlumeSignature.html).
/// [`plume_rustcrypto::AffinePoint`](https://docs.rs/plume_rustcrypto/latest/plume_rustcrypto/struct.AffinePoint.html) is represented as a `Uint8Array` containing SEC1 encoded point.
/// [`plume_rustcrypto::NonZeroScalar`](https://docs.rs/plume_rustcrypto/latest/plume_rustcrypto/type.NonZeroScalar.html) is represented as a `Uint8Array` containing SEC1 DER secret key.
/// `Option` can be `undefined` or instance of [`PlumeSignatureV1Fields`].
pub struct PlumeSignature {
    pub message: Vec<u8>,
    pub pk: Vec<u8>,
    pub nullifier: Vec<u8>,
    pub c: Vec<u8>,
    pub s: Vec<u8>,
    pub v1specific: Option<PlumeSignatureV1Fields>,
}

#[wasm_bindgen(getter_with_clone)]
/// @typedef {Object} PlumeSignatureV1Fields - Wrapper around [`plume_rustcrypto::PlumeSignatureV1Fields`](https://docs.rs/plume_rustcrypto/latest/plume_rustcrypto/struct.PlumeSignatureV1Fields.html).
#[derive(Clone)]
pub struct PlumeSignatureV1Fields {
    pub r_point: Vec<u8>,
    pub hashed_to_curve_r: Vec<u8>,
}
#[wasm_bindgen()]
impl PlumeSignatureV1Fields {
    #[wasm_bindgen(constructor)]
    pub fn new(r_point: Vec<u8>, hashed_to_curve_r: Vec<u8>) -> PlumeSignatureV1Fields {
        PlumeSignatureV1Fields {
            r_point,
            hashed_to_curve_r,
        }
    }
}

#[wasm_bindgen]
impl PlumeSignature {
    /// there's no case for constructing it from values, so this only used internally and for testing
    /// `v1specific` discriminates if it's V1 or V2 scheme used. Pls, see wrapped docs for details.
    #[wasm_bindgen(constructor)]
    pub fn new(
        message: Vec<u8>,
        pk: Vec<u8>,
        nullifier: Vec<u8>,
        c: Vec<u8>,
        s: Vec<u8>,
        v1specific: Option<PlumeSignatureV1Fields>,
    ) -> PlumeSignature {
        PlumeSignature {
            /* I really wonder how good is this pattern. But taking so much of args isn't good, and builder pattern seems redundant as all
            of the fields are required, and setters are just assignments. */
            //      Actually there's no case for constructing it from values, so this only used internally and for testing.
            message,
            pk,
            nullifier,
            c,
            s,
            v1specific, //: if v1specific.is_falsy() {None} else {Some(v1specific)}
        }

        // js_sys::Object::from_entries(&values)?
        // values.get
    }

    #[wasm_bindgen(js_name = zeroizePrivateParts)]
    /// Zeroize private values of the object from Wasm memory.
    pub fn zeroize_privateparts(&mut self) {
        self.c.zeroize();
        self.pk.zeroize();
    }
    #[wasm_bindgen(js_name = zeroizeAll)]
    /// Zeroize all values of the object from Wasm memory.
    pub fn zeroize_all(&mut self) {
        self.zeroize_privateparts();
        self.message.zeroize();
        self.nullifier.zeroize();
        self.s.zeroize();
        if let Some(v1) = self.v1specific.as_mut() {
            v1.hashed_to_curve_r.zeroize();
            v1.r_point.zeroize();
        }
    }

    #[cfg(feature = "verify")]
    /// @deprecated Use this only for testing purposes.
    /// @throws an error if the data in the object doesn't let it to properly run verification; message contains nature of the problem and indicates relevant property of the object. In case of other (crypto) problems returns `false`.
    pub fn verify(self) -> Result<bool, JsError> {
        Ok(plume_rustcrypto::PlumeSignature::verify(&self.try_into()?))
    }
}

#[wasm_bindgen(skip_jsdoc)]
/// @throws a "crypto error" in case of a problem with the secret key
/// @param {boolean} v1 - is the flag to choose between V1 and V2 output.
/// @param {Uint8Array} sk - secret key in SEC1 DER format.
/// @param {Uint8Array} msg
/// @returns {PlumeSignature}
pub fn sign(v1: bool, sk: &mut [u8], msg: &[u8]) -> Result<PlumeSignature, JsError> {
    let sk_z = plume_rustcrypto::SecretKey::from_sec1_der(sk)?;
    sk.zeroize();
    let signer = plume_rustcrypto::randomizedsigner::PlumeSigner::new(&sk_z, v1);

    Ok(signer
        .sign_with_rng(&mut signature::rand_core::OsRng, msg)
        .into())
}

impl From<plume_rustcrypto::PlumeSignature> for PlumeSignature {
    fn from(value: plume_rustcrypto::PlumeSignature) -> Self {
        PlumeSignature {
            message: value.message,
            pk: value.pk.to_encoded_point(true).as_bytes().to_vec(),
            nullifier: value.nullifier.to_encoded_point(true).as_bytes().to_vec(),
            c: plume_rustcrypto::SecretKey::from(value.c).to_sec1_der().expect("`k256` restricts this type to proper keys, so it's serialized representation shouldn't have a chance to fail")
                .to_vec(),
            s: plume_rustcrypto::SecretKey::from(value.s).to_sec1_der().expect("`k256` restricts this type to proper keys, so it's serialized representation shouldn't have a chance to fail")
                .to_vec(),
            v1specific: value.v1specific.map(|v1| {PlumeSignatureV1Fields {
                r_point: v1.r_point.to_encoded_point(true).as_bytes().to_vec(),
                hashed_to_curve_r: v1.hashed_to_curve_r.to_encoded_point(true).as_bytes().to_vec(),
            }})
        }
    }
}

#[wasm_bindgen(js_name = sec1DerScalarToBigint)]
/// This might leave values in memory! Don't use for private values.
/// JS most native format for scalar is `BigInt`, but it's not really transportable or secure, so for uniformity of approach `s` in `PlumeSignature` is defined similar to `c`;
/// but if you want to have it as a `BigInt` this util is left here.
pub fn sec1derscalar_to_bigint(scalar: &[u8]) -> Result<js_sys::BigInt, JsError> {
    Ok(js_sys::BigInt::new(&JsValue::from_str(
        ("0x".to_owned()
            + plume_rustcrypto::SecretKey::from_sec1_der(scalar)?
                .to_nonzero_scalar()
                .to_string()
                .as_str())
        .as_str(),
    ))
    .expect(
        "`BigInt` always can be created from hex string, and `v.to_string()` always produce that",
    ))
}

// TODO deprecate when `verify` gone
#[cfg(feature = "verify")]
impl TryInto<plume_rustcrypto::PlumeSignature> for PlumeSignature {
    type Error = JsError;

    fn try_into(self) -> Result<plume_rustcrypto::PlumeSignature, Self::Error> {
        let point_check = |point_bytes: Vec<u8>| -> Result<AffinePoint, anyhow::Error> {
            let point_encoded = sec1::point::EncodedPoint::from_bytes(point_bytes)?; // TODO improve formatting (quotes e.g.)
            let result = plume_rustcrypto::AffinePoint::from_encoded_point(&point_encoded);
            if result.is_none().into() {
                Err(anyhow::Error::msg("the point isn't on the curve"))
            } else {
                Ok(result.expect("`None` is processed the line above"))
            }
        };

        let err_field_wrap = |name_field: &str, er: anyhow::Error| -> JsError {
            JsError::new(
                ("while proccessing ".to_owned() + name_field + " :" + er.to_string().as_str())
                    .as_str(),
            )
        };

        Ok(plume_rustcrypto::PlumeSignature {
            message: self.message,
            pk: point_check(self.pk).map_err(|er| err_field_wrap("`pk`", er))?,
            // plume_rustcrypto::AffinePoint::try_from(self.pk)?, //.try_into<[u8; 33]>()?.into(),
            nullifier: point_check(self.nullifier)
                .map_err(|er| err_field_wrap("`nullifier`", er))?,
            c: plume_rustcrypto::SecretKey::from_sec1_der(&self.c)?.into(),
            s: plume_rustcrypto::SecretKey::from_sec1_der(&self.s)?.into(), //scalar_from_bigint(self.s).map_err(|er| err_field_wrap("`s`", er))?,
            v1specific: if let Some(v1) = self.v1specific {
                Some(plume_rustcrypto::PlumeSignatureV1Fields {
                    r_point: point_check(v1.r_point)
                        .map_err(|er| err_field_wrap("`r_point`", er))?,
                    hashed_to_curve_r: point_check(v1.hashed_to_curve_r)
                        .map_err(|er| err_field_wrap("`hashed_to_curve_r`", er))?,
                })
            } else {
                None
            },
        })
    }
}
