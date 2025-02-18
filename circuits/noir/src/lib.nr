use nodash::array::pack_bytes;
use noir_bigcurve::BigCurveTrait;
use noir_bigcurve::scalar_field::ScalarField;
use std::hash::poseidon2::Poseidon2::hash;

comptime global COMPRESSED_SIZE_BYTES: u32 = 33;

pub struct Plume<BC, let NScalarSlices: u32, let L: u32> {
    msg: [u8; L],
    c: ScalarField<NScalarSlices>,
    s: ScalarField<NScalarSlices>,
    pk: BC,
    nullifier: BC,
}

trait PlumeVerifier<BC, let NScalarSlices: u32, let L: u32> {
    fn new(
        msg: [u8; L],
        c: ScalarField<NScalarSlices>,
        s: ScalarField<NScalarSlices>,
        pk: BC,
        nullifier: BC,
    ) -> Plume<BC, NScalarSlices, L>;
    fn plume_v1(self) -> Field;
    fn plume_v2(self) -> (BC, BC);
    fn check_ec_equations(self) -> (BC, BC, BC);
    fn form_plume_msg(self) -> [u8; L + COMPRESSED_SIZE_BYTES];
    fn compress_ec_point(self, point: BC) -> [u8; COMPRESSED_SIZE_BYTES];
    fn poseidon_12_coordinates(self, h: BC, gr: BC, hr: BC) -> Field;
}

impl<BC, let NScalarSlices: u32, let L: u32> PlumeVerifier<BC, NScalarSlices, L> for Plume<BC, NScalarSlices, L>
where
    BC: BigCurveTrait<_> + std::ops::Sub,
{
    fn new(
        msg: [u8; L],
        c: ScalarField<NScalarSlices>,
        s: ScalarField<NScalarSlices>,
        pk: BC,
        nullifier: BC,
    ) -> Plume<BC, NScalarSlices, L> {
        let plume = Plume { msg, c, s, pk, nullifier };
        plume
    }

    fn plume_v1(self) -> Field {
        let (r_point, hashed_to_curve_r, hashed_to_curve) = self.check_ec_equations();

        self.poseidon_12_coordinates(hashed_to_curve, r_point, hashed_to_curve_r)
    }

    fn plume_v2(self) -> (BC, BC) {
        let (r_point, hashed_to_curve_r, _) = self.check_ec_equations();

        (r_point, hashed_to_curve_r)
    }

    fn check_ec_equations(self) -> (BC, BC, BC) {
        let s_point = BC::one().mul(self.s);
        let r_point = s_point - self.pk.mul(self.c);

        let plume_msg = self.form_plume_msg();
        let hashed_to_curve = BC::hash_to_curve(plume_msg);
        let h_pow_s = hashed_to_curve.mul(self.s);
        let hashed_to_curve_r = h_pow_s - self.nullifier.mul(self.c);

        (r_point, hashed_to_curve_r, hashed_to_curve)
    }

    fn form_plume_msg(self) -> [u8; L + COMPRESSED_SIZE_BYTES] {
        let mut plume_msg = [0; L + COMPRESSED_SIZE_BYTES];

        for i in 0..self.msg.len() {
            plume_msg[i] = self.msg[i];
        }

        let compressed_pk = self.compress_ec_point(self.pk);
        for i in 0..COMPRESSED_SIZE_BYTES {
            plume_msg[self.msg.len() + i] = compressed_pk[i];
        }

        plume_msg
    }

    fn compress_ec_point(self, point: BC) -> [u8; COMPRESSED_SIZE_BYTES] {
        let x: [u8; 32] = point.x().to_le_bytes();
        let mut compressed = [0 as u8; COMPRESSED_SIZE_BYTES];

        let sign = point.y().to_le_bytes::<32>()[0] & 1;
        compressed[0] = sign + 2; // convention to encode `y` as 02 or 03
        for i in 0..32 {
            compressed[32 - i] = x[i];
        }

        compressed
    }

    fn poseidon_12_coordinates(self, h: BC, gr: BC, hr: BC) -> Field {
        let mut compressed = [[0 as u8; COMPRESSED_SIZE_BYTES]; 6];
        compressed[0] = self.compress_ec_point(BC::one());
        compressed[1] = self.compress_ec_point(self.pk);
        compressed[2] = self.compress_ec_point(h);
        compressed[3] = self.compress_ec_point(self.nullifier);
        compressed[4] = self.compress_ec_point(gr);
        compressed[5] = self.compress_ec_point(hr);

        // Concatenate
        let mut res = [0 as u8; COMPRESSED_SIZE_BYTES * 6];
        for i in 0..6 {
            for j in 0..COMPRESSED_SIZE_BYTES {
                res[i * COMPRESSED_SIZE_BYTES + j] = compressed[i][j];
            }
        }

        let packed_res = pack_bytes(res);

        hash(packed_res, packed_res.len())
    }
}

mod test {
    use crate::Plume;
    use noir_bigcurve::curves::secp256k1::{
        Secp256k1, Secp256k1_Params, Secp256k1Fq, Secp256k1Fr, Secp256k1Scalar,
    };
    use noir_bigcurve::scalar_field::ScalarField;

    #[test]
    fn test_plume_v2_2() {
        let msg = [115, 105, 103, 110, 84, 104, 105, 115];

        let c2 = Secp256k1Fq::from_be_bytes([
            25, 48, 148, 152, 196, 123, 193, 9, 209, 58, 83, 106, 175, 140, 40, 48, 149, 237, 34, 2,
            125, 148, 106, 54, 114, 7, 22, 131, 174, 188, 105, 208,
        ]);
        let c2: Secp256k1Scalar = ScalarField::from_bignum(c2);

        let s2 = Secp256k1Fq::from_be_bytes([
            232, 126, 194, 99, 71, 55, 87, 146, 72, 134, 247, 82, 158, 229, 140, 149, 111, 138, 153,
            2, 105, 222, 70, 22, 34, 41, 70, 212, 47, 29, 185, 219,
        ]);
        let s2: Secp256k1Scalar = ScalarField::from_bignum(s2);

        let sk = Secp256k1Fq::from_be_bytes([
            172, 9, 116, 190, 195, 154, 23, 227, 107, 164, 166, 180, 210, 56, 255, 148, 75, 172,
            180, 120, 203, 237, 94, 252, 174, 120, 77, 123, 244, 242, 255, 128,
        ]);
        let sk: Secp256k1Scalar = ScalarField::from_bignum(sk);

        let pk = Secp256k1::one().mul(sk);

        let H = Secp256k1 {
            x: Secp256k1Fq::from_slice([
                0x2affbc49c54d1136a2190db0800b65,
                0x2d0e12679f23c218889395abcdc01f,
                0xbcac,
            ]),
            y: Secp256k1Fq::from_slice([
                0xa91a53e32b3752145d87f0cd70966e,
                0xb339c974c0e757d348081f90a123b0,
                0x3bcf,
            ]),
            is_infinity: false,
        };
        let nullifier = H.mul(sk);

        let plume = Plume::new(msg, c2, s2, pk, nullifier);
        let (_, _) = plume.plume_v2();
    }
}
