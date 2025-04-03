pragma circom 2.0.0;

include "lib/check_merkle_tree_zkf.circom";
include "lib/check_key_introduce_zkf.circom";
include "lib/circomlib/eddsaposeidon.circom";
include "lib/generate_keys_introduce1_zkf.circom";
include "lib/encrypt_introduce1_zkf.circom";

/*
Circuit to verify IP and RVP's policy. We've replaced Tor cryptographical functions with zk-friendly functions
to test the performance of a theorical implementation with zk-friendly primitives.

SHA3 and SHAKE256 --> Poseidon
Ed25519 --> EdDSA in Baby Jubjub + Poseidon
AES256-CTR --> ChaCha20 (Not zk-friendly per se, but performs better)

kp_hs_id and blinded_key are now BabyJubjub public keys

*/

template IP_ZKF(ip_depth, rvp_depth, plaintext_length, start_key_byte){
    signal input kp_hs_id_x;
    signal input kp_hs_id_y;
    signal input blinded_key_x;
    signal input blinded_key_y;
    signal input rvp_key_x;
    signal input rvp_key_y;
    signal input intro_secret_hs_input; // Used for key generation

    // IP and RVP Merkle Tree inputs
    signal input ip_root;
    signal input ip_path_indexes[ip_depth];
    signal input ip_path[ip_depth];
    signal input rvp_root; 
    signal input rvp_path_indexes[rvp_depth];
    signal input rvp_path[rvp_depth];

    // RVP root signature
    signal input S;
    signal input R8x;
    signal input R8y;

    signal input plaintext[plaintext_length];
    signal input encrypted[plaintext_length];

    // 1. Verify both Merkle Trees
    component ip_mt = CheckMerkleTree_ZKF(ip_depth);
    ip_mt.root <== ip_root;
    ip_mt.key[0] <== kp_hs_id_x;
    ip_mt.key[1] <== kp_hs_id_y;
    ip_mt.path <== ip_path;
    ip_mt.path_indexes <== ip_path_indexes;
    
    component rvp_mt = CheckMerkleTree_ZKF(rvp_depth);
    rvp_mt.root <== rvp_root;
    rvp_mt.key[0] <== kp_hs_id_x;
    rvp_mt.key[1] <== kp_hs_id_y;
    rvp_mt.path <== rvp_path;
    rvp_mt.path_indexes <== rvp_path_indexes;

    // 2. Verify RVP signature
    component verify = EdDSAPoseidonVerifier();
    verify.enabled <== 1;
    verify.Ax <== rvp_key_x;
    verify.Ay <== rvp_key_y;
    verify.S <== S;
    verify.R8x <== R8x;
    verify.R8y <== R8y;
    verify.M <== rvp_root;

    // 3. Check that RVP key is in plaintext
    component ck = CheckKeyIntroduce1_ZKF(plaintext_length, start_key_byte);
    ck.key_x <== rvp_key_x;
    ck.key_y <== rvp_key_y;
    ck.plaintext <== plaintext;
    
    // 4. Generate encryption key
    component keygen = GenerateKeyIntroduce1_ZKF();
    keygen.kp_hs_id_x <== kp_hs_id_x;
    keygen.kp_hs_id_y <== kp_hs_id_y;
    keygen.blinded_key_x <== blinded_key_x;
    keygen.blinded_key_y <== blinded_key_y;
    keygen.intro_secret_hs_input <== intro_secret_hs_input;

    // 5. Encrypt plaintext
    component cypher = EncryptIntroduce1_ZKF(plaintext_length);
    cypher.plaintext <== plaintext;
    cypher.key <== keygen.out;

    // 6. Compare to input encrypted plaintext
    component feq[plaintext_length];
    var n_blocks = plaintext_length / 4;
    var k = 0;
    for(var i = 0; i < n_blocks; i++){
        for(var j = 0; j < 4; j++){
            feq[k] = ForceEqual();
            feq[k].in[0] <== encrypted[k];
            feq[k].in[1] <== cypher.out[i][j];
            k++;
        }
    }
}

component main {public [ip_root]} = IP_ZKF(14, 14, 192, 26);