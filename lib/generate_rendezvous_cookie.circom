pragma circom 2.0.0;

include "circomlib/poseidon.circom";
include "circomlib/bitify.circom";
include "utils_bytes.circom";
include "utils.circom";

// Generates Rendesvouz cookie
// kp_hs_id is passed represented as two 128 bits halves
template GenRevCookie(){
    signal input kp_hs_id[2];
    signal input time_period;
    signal input time_period_length;
    signal input rvp_id_fingerprint;
    signal input nonce;

    signal output out[20];

    component poseidon = Poseidon(6);
    poseidon.inputs[0] <== kp_hs_id[0];
    poseidon.inputs[1] <== kp_hs_id[1];
    poseidon.inputs[2] <== rvp_id_fingerprint;
    poseidon.inputs[3] <== time_period;
    poseidon.inputs[4] <== time_period_length;
    poseidon.inputs[5] <== nonce;

    // Truncate output to 20 bytes
    component n2b = Num2Bits_strict();
    n2b.in <== poseidon.out;

    component pack = PackBytes(20);
    for(var i = 0; i < 160; i++){
        pack.bits[i] <== n2b.out[i]; 
    }

    out <== pack.bytes;
}