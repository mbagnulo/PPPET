pragma circom 2.0.0;

include "circomlib/poseidon.circom";
include "circomlib/bitify.circom";

/*
We'll change the key generation to:

N_hs_subcred = Poseidon("subcredential" | N_hs_cred | blinded-public-key).
N_hs_cred = Poseidon("credential" | public-identity-key)
hs_keys = Poseidon(intro_secret_hs_input | t_hsenc | info, S_KEY_LEN)

info = m_hsexpand | N_hs_subcred
t_hsenc = "tor-hs-ntor-curve25519-sha3-256-1:hs_key_extract"
m_sexpand = "tor-hs-ntor-curve25519-sha3-256-1:hs_key_expand"

As before, we'll pass intro_secret_hs_input (represented as a finite field element) and the blinded key as an inputs.
*/

template GenerateKeyIntroduce1_ZKF(){
    signal input kp_hs_id_x;
    signal input kp_hs_id_y;
    signal input blinded_key_x;
    signal input blinded_key_y;
    signal input intro_secret_hs_input;

    signal output out[256];

    // String constants as finite field elements (String --> Bytes (ASCII) --> Int % p)
    var credential = 469624516704518340698476;
    var subcredential = 9147567379644335134475815575916;
    var m_hsexpand = 15585471654678358976082026826793460347636303512619410008603145572726714815514;
    var t_hsenc = 6220540922911807428153022022301782879091378354850711649332104661259310799038;
 
    // N_hs_cred
    component poseidon_1 = Poseidon(3);
    poseidon_1.inputs[0] <== credential;
    poseidon_1.inputs[1] <== kp_hs_id_x;
    poseidon_1.inputs[2] <== kp_hs_id_y;

    // N_hs_subcred
    // We could also verify that blinded key is correctly generated from kp_hs_id since now it is way cheaper, but
    // it shouldn't be necessary
    component poseidon_2 = Poseidon(4);
    poseidon_2.inputs[0] <== subcredential;
    poseidon_2.inputs[1] <== poseidon_1.out;
    poseidon_2.inputs[2] <== blinded_key_x;
    poseidon_2.inputs[3] <== blinded_key_y;

    // hs_keys to LE bits
    // The key is actually 253 bits, since 2^252 < p < 2^253. If this is an issue, you could always generate the
    // last 3 bits for example with a hash function
    component poseidon_3 = Poseidon(4);
    poseidon_3.inputs[0] <== intro_secret_hs_input;
    poseidon_3.inputs[1] <== t_hsenc;
    poseidon_3.inputs[2] <== m_hsexpand;
    poseidon_3.inputs[3] <== poseidon_2.out;

    component n2b = Num2Bits(256);
    n2b.in <== poseidon_3.out;
    out <== n2b.out;
}