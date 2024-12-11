template IP(depth, key_index, inner_length, outer_length, encrypted_index){
    signal input kp_hs_id[32];
    // ...

    // Check that kp_hs_id is on IP allow list
    component merkle_tree = CheckMerkleTree(depth);
    merkle_tree.rt <== rt;
    merkle_tree.leaf <== kp_hs_id;
    merkle_tree.path <== path;
    merkle_tree.indexes <== indexes;

    // Check that input blinded key corresponds to the one calculated with kp_hs_id
    component check_bkey = CheckBlindedKey();
    check_bkey.id_key <== kp_hs_id;
    check_bkey.id_key_enc <== kp_hs_id_encoded;
    check_bkey.bl_key <== blinded_key;
    check_bkey.prd[0] <== period_number;
    check_bkey.prd[1] <== period_length;
    
    // Verify signature
    component verify = Ed25519Verifier(256);
    verify.msg <== rt;
    verify.A <== ip_key;
    verify.R8 <== R;
    verify.S <== S;
    verify.PointA <== ip_key_encoded;
    verify.PointR <== R_encoded;

    1 === verify.out;

    // Check that IP key is in descriptor
    component check_key = FindKeyDescriptor(key_index, inner_length);
    check_key.plaintext <== inner_plaintext;
    check_key.ip_key <== ip_key;

    // Obtain keys and IVs for encrpytion
    component keygen = GenerateKeys();
    keygen.id_key <== kp_hs_id;
    keygen.bl_key <== blinded_key;
    keygen.salts[0] <== inner_salt;
    keygen.salts[1] <== outer_salt;
    keygen.rev_counter <== rev_counter;

    // Check that the "encrypted" field in the outer layer is correct
    component check_outer = CheckOuterLayer(inner_length, outer_length, encrypted_index);
    check_outer.outer_layer <== outer_plaintext;
    check_outer.enc <== encrypted;

    // Encrypt inner layer and outer layer plaintext
    component enc = EncryptLayers(inner_length, outer_length);
    enc.inner_pt <== inner_plaintext;
    enc.key[0] <== keygen.inner_key;
    enc.key[1] <== keygen.outer_key;
    enc.iv[0] <== keygen.inner_iv;
    enc.iv[1] <== keygen.outer_iv;

    // Compare calculated layers to the "encrypted" and "superencrpyted" fields
    component compare = CompareLayers(inner_length, outer_length);
    compare.enc_field <== encrypted;
    compare.inner_layer <== enc.inner_result;
    compare.superenc_field <== superencrypted;
    compare.outer_layer <== enc.outer_result;
}