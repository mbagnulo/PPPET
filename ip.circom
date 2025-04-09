pragma circom 2.0.0;

include "lib/check_merkle_tree.circom";
include "lib/generate_keys_introduce1.circom";
include "lib/encrypt_introduce1.circom";

/* 
    Circuit used by IPs to verify their own policies when receiving an INTRODUCE1 message from a client
*/

template IP(ip_depth, plaintext_length){
    signal input kp_hs_id[32]; // Hidden service identity public key in bytes
    signal input blinded_key[32]; // Hidden service blinded key in bytes

    // IP Merkle Tree inputs
    signal input ip_root;
    signal input ip_path_indexes[ip_depth];
    signal input ip_path[ip_depth];

    signal input plaintext[plaintext_length]; // INTRODUCE1 cell plaintext in bytes
    signal input intro_secret_hs_input[129]; // intro_secret_hs_input in bytes
    signal input encrypted[plaintext_length*8]; // Encrypted plaintext in bits

    // Transform kp_hs_id into bits
    signal kp_bits[256];
    component unpack = UnpackBytes(32);
    unpack.bytes <== kp_hs_id;
    kp_bits <== unpack.bits;

    // Verify IP policy
    component ip_mt = CheckMerkleTree(ip_depth);
    ip_mt.root <== ip_root;
    ip_mt.kp_bits <== kp_bits;
    ip_mt.path <== ip_path;
    ip_mt.path_indexes <== ip_path_indexes;
    
    // Generate encryption key
    signal key[256];
    component calculate_key = GenerateKeyIntroduce1();
    calculate_key.kp_hs_id <== kp_hs_id;
    calculate_key.blinded_key <== blinded_key;
    calculate_key.intro_secret_hs_input <== intro_secret_hs_input;
    key <== calculate_key.key;
    
    // Encrypt plaintext with key
    component cipher = EncryptIntroduce1(plaintext_length);
    cipher.plaintext <== plaintext;
    cipher.key <== key;

    // Check that the encrypted part of the INTRODUCE1 cell and the calculated encrypted plaintext are the same
    component feq = ForceEqualArrays(plaintext_length*8);
    feq.array1 <== encrypted;
    feq.array2 <== cipher.out;
}

component main {public [ip_root, encrypted]} = IP(14, 432);
