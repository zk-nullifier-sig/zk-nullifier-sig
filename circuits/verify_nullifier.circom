pragma circom 2.1.2;

include "./node_modules/circom-ecdsa/circuits/ecdsa.circom";
include "./node_modules/circom-ecdsa/circuits/secp256k1.circom";
include "./node_modules/circom-ecdsa/circuits/secp256k1_func.circom";
include "./node_modules/secp256k1_hash_to_curve_circom/circom/hash_to_curve.circom";
include "./node_modules/circomlib/circuits/bitify.circom";

// Verifies that a nullifier belongs to a specific public key
// This blog explains the intuition behind the construction https://blog.aayushg.com/posts/nullifier
template verify_nullifier(n, k, msg_length) {
    signal input s[k];
    signal input msg[msg_length];
    signal input public_key[2][k];
    signal input nullifier[2][k];

    // precomputed values for the hash_to_curve component
    signal input q0_gx1_sqrt[4];
    signal input q0_gx2_sqrt[4];
    signal input q0_y_pos[4];
    signal input q0_x_mapped[4];
    signal input q0_y_mapped[4];

    signal input q1_gx1_sqrt[4];
    signal input q1_gx2_sqrt[4];
    signal input q1_y_pos[4];
    signal input q1_x_mapped[4];
    signal input q1_y_mapped[4];

    // calculate g^r
    // g^r = g^s / pk^c (where g is the generator)
    // Note this implicitly checks the first equation in the blog

    // Calculates g^s. Note, turning a private key to a public key is the same operation as
    // raising the generator g to some power, and we are *not* dealing with private keys in this circuit.
    component g_pow_s = ECDSAPrivToPub(n, k);
    for (var i = 0; i < k; i++) {
        g_pow_s.privkey[i] <== s[i];
    }

    component g_pow_r = a_div_b_pow_c(n, k);
    for (var i = 0; i < k; i++) {
        g_pow_r.a[0][i] <== g_pow_s.pubkey[0][i];
        g_pow_r.a[1][i] <== g_pow_s.pubkey[1][i];
        g_pow_r.b[0][i] <== public_key[0][i];
        g_pow_r.b[1][i] <== public_key[1][i];
        g_pow_r.c[i] <== c[i];
    }

    // Calculate hash[m, pk]^r
    // hash[m, pk]^r = hash[m, pk]^s / (hash[m, pk]^sk)^c
    // Note this implicitly checks the second equation in the blog

    // Calculate hash[m, pk]^r
    component h = HashToCurve(msg_length + 33);
    for (var i = 0; i < msg_length; i++) {
        h.msg[i] <== msg[i];
    }

    component pk_compressor = compress_ec_point(n, k);
    for (var i = 0; i < 2; i++) {
        for (var j = 0; j < k; j++) {
            pk_compressor.uncompressed[i][j] <== public_key[i][j];
        }
    }

    for (var i = 0; i < 33; i++) {
        h.msg[msg_length + i] <== pk_compressor.compressed[i];
    }

    // Input precalculated values into HashToCurve
    for (var i = 0; i < k; i++) {
        h.q0_gx1_sqrt[i] <== q0_gx1_sqrt[i];
        h.q0_gx2_sqrt[i] <== q0_gx2_sqrt[i];
        h.q0_y_pos[i] <== q0_y_pos[i];
        h.q0_x_mapped[i] <== q0_x_mapped[i];
        h.q0_y_mapped[i] <== q0_y_mapped[i];
        h.q1_gx1_sqrt[i] <== q1_gx1_sqrt[i];
        h.q1_gx2_sqrt[i] <== q1_gx2_sqrt[i];
        h.q1_y_pos[i] <== q1_y_pos[i];
        h.q1_x_mapped[i] <== q1_x_mapped[i];
        h.q1_y_mapped[i] <== q1_y_mapped[i];
    }

    component h_pow_s = Secp256k1ScalarMult(n, k);
    for (var i = 0; i < k; i++) {
        h_pow_s.scalar[i] <== s[i];
        h_pow_s.point[0][i] <== h.out[0][i];
        h_pow_s.point[1][i] <== h.out[1][i];
    }

    component h_pow_r = a_div_b_pow_c(n, k);
    for (var i = 0; i < k; i++) {
        h_pow_r.a[0][i] <== h_pow_s.out[0][i];
        h_pow_r.a[1][i] <== h_pow_s.out[1][i];
        h_pow_r.b[0][i] <== nullifier[0][i];
        h_pow_r.b[1][i] <== nullifier[1][i];
        h_pow_r.c[i] <== c[i];
    }
}

template a_div_b_pow_c(n, k) {
    signal input a[2][k];
    signal input b[2][k];
    signal input c[k];
    signal output out[2][k];

    // Calculates b^c. Note that the spec uses multiplicative notation to preserve intuitions about
    // discrete log, and these comments follow the spec to make comparison simpler. But the circom-ecdsa library uses
    // additive notation. This is why we appear to calculate an expnentiation using a multiplication component.
    component b_pow_c = Secp256k1ScalarMult(n, k);
    for (var i = 0; i < k; i++) {
        b_pow_c.scalar[i] <== c[i];
        b_pow_c.point[0][i] <== b[0][i];
        b_pow_c.point[1][i] <== b[1][i];
    }

    // Calculates inverse of b^c by finding the modular inverse of its y coordinate
    var prime[100] = get_secp256k1_prime(n, k);
    component b_pow_c_inv_y = BigSub(n, k);
    for (var i = 0; i < k; i++) {
        b_pow_c_inv_y.a[i] <== prime[i];
        b_pow_c_inv_y.b[i] <== b_pow_c.out[1][i];
    }
    b_pow_c_inv_y.underflow === 0;

    // Calculates a^s * (b^c)-1
    component final_result = Secp256k1AddUnequal(n, k);
    for (var i = 0; i < k; i++) {
        final_result.a[0][i] <== a[0][i];
        final_result.a[1][i] <== a[1][i];
        final_result.b[0][i] <== b_pow_c.out[0][i];
        final_result.b[1][i] <== b_pow_c_inv_y.out[i];
    }

    for (var i = 0; i < k; i++) {
        out[0][i] <== final_result.out[0][i];
        out[1][i] <== final_result.out[1][i];
    }
}

// We use elliptic curve points in uncompressed form to do elliptic curve arithmetic, but we use them in compressed form when
// hashing to save constraints (as hash cost is generally parameterised in the input length).
// Elliptic curves are symmteric about the x-axis, and for every possible x coordinate there are exactly
// 2 possible y coordinates. Over a prime field, one of those points is even and the other is odd.
// The convention is to represent the even point with the byte 02, and the odd point with the byte 03.
// Because our hash functions work over bytes, our output is a 33 byte array.
template compress_ec_point(n, k) {
    assert(n == 64 && k == 4);
    signal input uncompressed[2][k];
    signal output compressed[33];

    compressed[0] <-- uncompressed[1][0] % 2 + 2;
    var bytes_per_register = 32/k;
    for (var i = 0; i < 32; i++) {
        compressed[32-i] <-- uncompressed[0][i \ bytes_per_register] \ (256 ** (i % bytes_per_register)) % 256;
    }

    component verify = verify_ec_compression(n, k);
    for (var i = 0; i < 2; i++) {
        for (var j = 0; j < k; j++) {
            verify.uncompressed[i][j] <== uncompressed[i][j];
        }
    }
    for (var i = 0; i < 33; i++) {
        verify.compressed[i] <== compressed[i];
    }
}

// We have a separate internal compression verification template for testing purposes. An adversarial prover
// can set any compressed values, so it's useful to be able to test adversarial inputs.
template verify_ec_compression(n, k) {
    signal input uncompressed[2][k];
    signal input compressed[33];

    // Get the bit string of the smallest register
    // Make sure the least significant bit's evenness matches the evenness specified by the first byte in the compressed version
    component num2bits = Num2Bits(n);
    num2bits.in <== uncompressed[1][0]; // Note, circom-ecdsa uses little endian, so we check the 0th register of the y value
    compressed[0] === num2bits.out[0] + 2;

    // Make sure the compressed and uncompressed x coordinates represent the same number
    // l_bytes is an algebraic expression for the bytes of each register
    var l_bytes[k];
    for (var i = 1; i < 33; i++) {
        var j = i - 1; // ignores the first byte specifying the compressed y coordinate
        l_bytes[j \ 8] += compressed[33-i] * (256 ** (j % 8));
    }

    for (var i = 0; i < k; i++) {
        uncompressed[0][i] === l_bytes[i];
    }
}

// Equivalent to get_gx and get_gy in circom-ecdsa, except we also have values for n = 64, k = 4.
// This is necessary because hash_to_curve is only implemented for n = 64, k = 4 but circom-ecdsa
// only g's coordinates for n = 86, k = 3
// TODO: merge this upstream into circom-ecdsa
function get_genx(n, k) {
    assert((n == 86 && k == 3) || (n == 64 && k == 4));
    var ret[100];
    if (n == 86 && k == 3) {
        ret[0] = 17117865558768631194064792;
        ret[1] = 12501176021340589225372855;
        ret[2] = 9198697782662356105779718;
    }
    if (n == 64 && k == 4) {
        ret[0] = 6481385041966929816;
        ret[1] = 188021827762530521;
        ret[2] = 6170039885052185351;
        ret[3] = 8772561819708210092;
    }
    return ret;
}

function get_geny(n, k) {
    assert((n == 86 && k == 3) || (n == 64 && k == 4));
    var ret[100];
    if (n == 86 && k == 3) {
        ret[0] = 6441780312434748884571320;
        ret[1] = 57953919405111227542741658;
        ret[2] = 5457536640262350763842127;
    }
    if (n == 64 && k == 4) {
        ret[0] = 11261198710074299576;
        ret[1] = 18237243440184513561;
        ret[2] = 6747795201694173352;
        ret[3] = 5204712524664259685;
    }
    return ret;
}
