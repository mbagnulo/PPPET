pragma circom 2.0.0;

include "circomlib/poseidon.circom";
include "circomlib/bitify.circom";
include "utils_bytes.circom";

// RENDESVOUZ_COOKIE = H(kp_hs_id | nonce | rvp_onion_key | time_period)
// We use time period + onion key to make a proof only valid for a specific RVP and a specific time period
// Onion key info: https://spec.torproject.org/tor-spec/relay-keys.html#circuit-extension-keys
// Time period info: https://spec.torproject.org/rend-spec/deriving-keys.html#TIME-PERIODS


// We are working in BN128, so we can't directly hash with Poseidon a 32 byte number
// Transforms 32 bytes key into 2 integers that can be hashed with Poseidon
template KeyToNum(){
    signal input in[32];
    signal output out[2];

    component up = UnpackBytes(32);
    up.bytes <== in;

    component b2n[2];
    b2n[0] = Bits2Num(128);
    b2n[1] = Bits2Num(128);

    for(var i = 0; i < 128; i++){
        b2n[0].in[i] <== up.bits[i];
        b2n[1].in[i] <== up.bits[i+128];
    }

    out[0] <== b2n[0].out;
    out[1] <== b2n[1].out;
}

// Generates Rendesvouz cookie
template GenRevCookie(){
    signal input kp_hs_id[32];
    signal input nonce; // Nonce sent by client
    signal input rvp_onion_key[32]; // RVP Circuit Onion key
    signal input time_period;

    signal output out[20];

    component k2n_1 = KeyToNum();
    k2n_1.in <== kp_hs_id;
    component k2n_2 = KeyToNum();
    k2n_2.in <== rvp_onion_key;

    component poseidon = Poseidon(6);
    poseidon.inputs[0] <== k2n_1.out[0];
    poseidon.inputs[1] <== k2n_1.out[1];
    poseidon.inputs[2] <== nonce;
    poseidon.inputs[3] <== k2n_2.out[0];
    poseidon.inputs[4] <== k2n_2.out[1];
    poseidon.inputs[5] <== time_period;

    // Truncate output to 20 bytes
    component n2b = Num2Bits(253);
    n2b.in <== poseidon.out;

    component pack = PackBytes(20);
    for(var i = 0; i < 160; i++){
        pack.bits[i] <== n2b.out[i];
    }

    out <== pack.bytes;
}