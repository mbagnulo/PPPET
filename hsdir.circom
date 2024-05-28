pragma circom 2.0.0;

include "lib/check_blinded_key.circom";
include "lib/check_merkle_tree.circom";

template HSDir(depth){
    signal input kp_bytes[32]; // kp_hs_id as an array of 32 bytes (le)

    signal input root; // Root of merkle tree
    signal input path_indexes[depth]; // Path selector to choose which direction to hash
    signal input path[depth]; // Path to the root

    signal input kp_base_85[4][3]; // Kp_hs_id in base 2^85
    signal input bkey_bytes[32]; // Blinded key in bytes (le)
    signal input period_number[8]; // Period number as an array of 8 bytes (le)
    signal input period_length[8]; // Period lenth as an array of 8 bytes (le)

    // Transform kp_hs_id to bits
    signal kp_bits[256];

    component unpack = UnpackBytes(32);
    unpack.bytes <== kp_bytes;
    kp_bits <== unpack.bits;

    // Check that kp_hs_id is on Merkle Tree 
    component merkle_tree = CheckMerkleTree(depth);
    merkle_tree.root <== root;
    merkle_tree.kp_bits <== kp_bits;
    merkle_tree.path <== path;
    merkle_tree.path_indexes <== path_indexes;

    // Check that the blinded key is the same as the one calculated with kp_hs_id
    component check_bkey = CheckBlindedKey();
    check_bkey.kp_bytes <== kp_bytes;
    check_bkey.kp_bits <== kp_bits;
    check_bkey.kp_base_85 <== kp_base_85;
    check_bkey.bkey_bytes <== bkey_bytes;
    check_bkey.period_number <== period_number;
    check_bkey.period_length <== period_length;    
}

// Depth of Merkle Tree is passed as argument, change accordingly
component main {public [root, bkey_bytes, period_number, period_length]} = HSDir(2);