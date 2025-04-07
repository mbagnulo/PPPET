pragma circom 2.0.0;

include "utils.circom";
include "circomlib/poseidon.circom";
include "hash_circuits/keccak/sha3_bytes.circom"; // for UnpackBytes

template CheckProofCommitment(){
    signal input commitment;
    signal input rvp_ed_key[32]; // RVP Ed25519's key found inside the INTRODUCE1 cell
    signal input rvp_jubjub_x;
    signal input rvp_jubjub_y;
    signal input nonce;

    // Check that H(ed_key | jubjub_key | nonce) = Public commitment

    // Convert Ed25519 key into 2 numbers for hashing with Poseidon
    component up = UnpackBytes(32);
    up.bytes <== rvp_ed_key;
    component b2n[2];
    b2n[0] = Bits2Num(128);
    b2n[1] = Bits2Num(128);
    
    var k = 128;
    for(var i = 0; i < 128; i++){
        b2n[0].in[i] <== up.bits[i];
        b2n[1].in[i] <== up.bits[k];
        k++;
    }
    
    component poseidon = Poseidon(5);
    poseidon.inputs[0] <== b2n[0].out;
    poseidon.inputs[1] <== b2n[1].out;
    poseidon.inputs[2] <== rvp_jubjub_x;
    poseidon.inputs[3] <== rvp_jubjub_y;
    poseidon.inputs[4] <== nonce;

    component feq = ForceEqual();
    feq.in[0] <== commitment;
    feq.in[1] <== poseidon.out;
}