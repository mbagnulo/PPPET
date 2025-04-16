pragma circom 2.0.0;

include "lib/check_blinded_key.circom";
include "lib/check_merkle_tree.circom";

template HSDir(depth){
    signal input kp_hs_id[32]; // kp_hs_id in bytes

    signal input root;
    signal input path[depth];
    signal input path_indexes[depth];

    signal input kp_base_85[4][3]; // Kp_hs_id in base 2^85
    signal input blinded_key[32]; // Blinded key in bytes
    signal input period_number[8]; // Period number as an array of 8 bytes
    signal input period_length[8]; // Period lenth as an array of 8 bytes

    // Check that kp_hs_id is in HSDir policy
    component mt = CheckMerkleTree(depth);
    mt.root <== root;
    mt.key <== kp_hs_id;
    mt.path <== path;
    mt.path_indexes <== path_indexes;

    // Compute blinded key and compare with public input
    component check_bkey = CheckBlindedKey();
    check_bkey.kp_hs_id <== kp_hs_id;
    check_bkey.kp_base_85 <== kp_base_85;
    check_bkey.blinded_key <== blinded_key;
    check_bkey.period_number <== period_number;
    check_bkey.period_length <== period_length;    
}

component main {public [root, blinded_key, period_number, period_length]} = HSDir(14);
