template HSDir(depth){
    signal input kp_hs_id[32];
    // ...

    // Check that kp_hs_id is on Merkle Tree 
    component merkle_tree = CheckMerkleTree(depth);
    merkle_tree.rt <== rt;
    merkle_tree.leaf <== kp_hs_id;
    merkle_tree.path <== path;
    merkle_tree.indexes <== indexes;

    // Check that the blinded key is the same as the one calculated with kp_hs_id
    component check_bkey = CheckBlindedKey();
    check_bkey.id_key <== kp_hs_id;
    check_bkey.id_key_enc <== kp_hs_id_encoded;
    check_bkey.bl_key <== blinded_key;
    check_bkey.prd[0] <== period_number;
    check_bkey.prd[1] <== period_length;    
}