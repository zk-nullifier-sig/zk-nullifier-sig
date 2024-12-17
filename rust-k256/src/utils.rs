use super::*;
use k256::{
    elliptic_curve::{
        hash2curve::{ExpandMsgXmd, GroupDigest},
        sec1::ToEncodedPoint,
    },
    ProjectivePoint, Secp256k1,
}; // requires 'getrandom' feature

// Hashes two values to the curve
pub(crate) fn hash_to_curve(
    m: &PlumeMessage,
    pk: &ProjectivePoint,
) -> Result<ProjectivePoint, k256::elliptic_curve::Error> {
    Secp256k1::hash_from_bytes::<ExpandMsgXmd<Sha256>>(
        &[[m.msg.as_slice(), &encode_pt(pk)].concat().as_slice()],
        //b"CURVE_XMD:SHA-256_SSWU_RO_",
        &[&m.dst],
    )
}

/// Encodes the point by compressing it to 33 bytes
pub(crate) fn encode_pt(point: &ProjectivePoint) -> Vec<u8> {
    point.to_encoded_point(true).to_bytes().to_vec()
}
