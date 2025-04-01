pragma circom 2.0.0;

include "lib/check_merkle_tree_zkf.circom";
include "lib/check_blinded_key_zkf.circom";

/*
Circuit to verify HSDir's policy. We've replaced Tor cryptographical functions with zk-friendly functions
to test the performance of a theorical implementation with zk-friendly primitives.

SHA3 --> Poseidon
Ed25519 --> EdDSA in Baby Jubjub + Poseidon

kp_hs_id is now a BabyJubjub public key

We pass period number and period length as ints
*/

template HSDir_ZKF(depth){
    // kp_hs_id and blinded_key as a public BabyJubjub keys
    signal input kp_hs_id_x;
    signal input kp_hs_id_y;
    signal input blinded_key_x;
    signal input blinded_key_y;
    
    signal input root;
    signal input path_indexes[depth];
    signal input path[depth];

    signal input period_number;
    signal input period_length;
    
    component mt = CheckMerkleTree_ZKF(depth);
    mt.key[0] <== kp_hs_id_x;
    mt.key[1] <== kp_hs_id_y;
    mt.root <== root;
    mt.path_indexes <== path_indexes;
    mt.path <== path;

    component check_bkey = CheckBlindedKey_ZKF();
    check_bkey.kp_hs_id_x <== kp_hs_id_x;
    check_bkey.kp_hs_id_y <== kp_hs_id_y;
    check_bkey.blinded_key_x <== blinded_key_x;
    check_bkey.blinded_key_y <== blinded_key_y;
    check_bkey.period_number <== period_number;
    check_bkey.period_length <== period_length;
}

component main {public [root, blinded_key_x, blinded_key_y, period_number, period_length]} = HSDir_ZKF(14);