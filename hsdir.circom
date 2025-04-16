pragma circom 2.0.0;

include "lib/check_blinded_key.circom";
include "lib/check_merkle_tree.circom";
include "lib/utils.circom";

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
    component gen_bkey = GenerateBlindedKey();
    gen_bkey.kp_hs_id <== kp_hs_id;
    gen_bkey.kp_base_85 <== kp_base_85;
    gen_bkey.blinded_key <== blinded_key;
    gen_bkey.period_number <== period_number;
    gen_bkey.period_length <== period_length;

    component feq = ForceEqualArrays(32);
    feq.array1 <== blinded_key;
    feq.array2 <== gen_bkey.out;    
}

component main {public [root, blinded_key, period_number, period_length]} = HSDir(14);
