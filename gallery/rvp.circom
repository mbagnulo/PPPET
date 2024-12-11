template RVP(depth, plaintext_length, key_index){
    signal input kp_hs_id[32];
    // ...

    // Check that kp_hs_id is on IP allow list
    component merkle_tree = CheckMerkleTree(depth);
    merkle_tree.rt <== rt;
    merkle_tree.leaf <== kp_hs_id;
    merkle_tree.path <== path;
    merkle_tree.indexes <== indexes;

    // Verify root signature with RVP key
    component verify = Ed25519Verifier(256);
    verify.msg <== rt;
    verify.A <== rvp_key;
    verify.R8 <== R;
    verify.S <== S;
    verify.PointA <== rvp_key_encoded;
    verify.PointR <== R_encoded;

    // Check that the RVP key is inside the plaintext
    component find_key = CheckIntroduce1(plaintext_length, key_index);
    find_key.in[0] <== plaintext;
    find_key.in[1] <== rvp_key;

    // Generate encryption key and encrypt plaintext
    component cipher = EncryptIntroduce1(plaintext_length);
    cipher.in_keys[0] <== kp_hs_id;
    cipher.in_keys[1] <== blinded_key;
    cipher.in_keys[2] <== client_pk;
    cipher.params <== intro_secret_hs;
    cipher.mac <== mac;
    cipher.plaintext <== plaintext;

    // Check that the encrypted part of the INTRODUCE1 cell and the calculated encrypted plaintext are the same
    component iseq = CompareArrays(encrypted_length);
    iseq.in[0] <== encrypted;
    iseq.in[1] <== cipher.out;

    iseq.out === 1;
}