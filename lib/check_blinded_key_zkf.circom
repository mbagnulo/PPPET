pragma circom 2.0.0;
include "circomlib/poseidon.circom";
include "circomlib/bitify.circom";
include "circomlib/escalarmulany.circom";

/*
Calculates blinded key and compares it to input for HSDir_ZKF
SHA3-256 --> Poseidon
Ed25519 Scalar Multiplication --> BabyJubJub Scalar Multiplication

For the string constants values, we've converted them to an integer and performed mod p
*/

template CheckBlindedKey_ZKF(){
    signal input kp_hs_id_x;
    signal input kp_hs_id_y;
    signal input blinded_key_x;
    signal input blinded_key_y;
    signal input period_number;
    signal input period_length;

    var BLIND_STRING = 1843959981176323709569765508481336882613113514525272461517351888976128;
    var ED25519_BASEPOINT = 4941924941743420924759303485883512835622371133134221925958648332926189230526;
    var KEYBLIND_STRING = 1981113541257683627620;

    // h = H(...)
    component poseidon = Poseidon(7);
    poseidon.inputs[0] <== BLIND_STRING;
    poseidon.inputs[1] <== kp_hs_id_x;
    poseidon.inputs[2] <== kp_hs_id_y;
    poseidon.inputs[3] <== ED25519_BASEPOINT;
    poseidon.inputs[4] <== KEYBLIND_STRING;
    poseidon.inputs[5] <== period_number;
    poseidon.inputs[6] <== period_length;

    component n2b = Num2Bits(253);
    n2b.in <== poseidon.out;

    // We assume kp_hs_id is in the subgroup and different to 0
    component mul = EscalarMulAny(253);
    mul.e <== n2b.out;
    mul.p[0] <== kp_hs_id_x;
    mul.p[1] <== kp_hs_id_y;

    // Compare
    component feq_x = ForceEqual();
    feq_x.in[0] <== blinded_key_x;
    feq_x.in[1] <== mul.out[0];

    component feq_y = ForceEqual();
    feq_y.in[0] <== blinded_key_y;
    feq_y.in[1] <== mul.out[1];

} 