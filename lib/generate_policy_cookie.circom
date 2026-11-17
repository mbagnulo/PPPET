pragma circom 2.0.0;

include "circomlib/poseidon.circom";
include "circomlib/bitify.circom";
include "utils_bytes.circom";
include "utils.circom";

// Generates POLICY_COOKIE
// kp_hs_id and auth_key are passed represented as two 128 bits halves
template GenPolicyCookie(){
    signal input kp_hs_id[2];
    signal input auth_key[2];
    signal input time_period;
    signal input time_period_length;
    signal input nonce;

    signal output out[32];

    component poseidon = Poseidon(7);
    poseidon.inputs[0] <== kp_hs_id[0];
    poseidon.inputs[1] <== kp_hs_id[1];
    poseidon.inputs[2] <== auth_key[0];
    poseidon.inputs[3] <== auth_key[1];
    poseidon.inputs[4] <== nonce;
    poseidon.inputs[5] <== time_period;
    poseidon.inputs[6] <== time_period_length;

    component n2b = Num2Bits_strict();
    n2b.in <== poseidon.out;

    component pack = PackBytes(32);
    for (var i = 0; i < 254; i++) {
        pack.bits[i] <== n2b.out[i];
    }

    // Add additional 2 bits until 32 bytes
    pack.bits[254] <== 0;
    pack.bits[255] <== 0;

    for (var i = 0; i < 32; i++) {
        out[i] <== pack.bytes[i];
    }

}