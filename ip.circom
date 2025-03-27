pragma circom 2.0.0;

include "lib/ed25519_circom/verify.circom";
include "lib/check_merkle_tree.circom";
include "lib/check_blinded_key.circom";
include "lib/check_key_introduce.circom";
include "lib/generate_keys_introduce1.circom";
include "lib/encrypt_introduce1.circom";

/* 
    Verifies IP's and RVP's policies in the IP
    - ip_depth & rvp_depth: Depths of IP and RVP Merkle Tree
    - plaintext_lengt: Length of INTRODUCE1 plaintext
    - start_key_byte: Index of first byte of the RVP key in the INTRODUCE1 cell plaintext

    Client must calculate RVP's Ed25519 key out of circuit
*/

template IP(ip_depth, rvp_depth, plaintext_length, start_key_byte){
    signal input kp_hs_id[32]; // Hidden service public key in bytes
    signal input blinded_key[32]; // Hidden service blinded key in bytes
    signal input kp_base_85[4][3]; // Kp_hs_id in base 2^85

    // IP and RVP Merkle Tree inputs
    signal input ip_root;
    signal input ip_path_indexes[ip_depth];
    signal input ip_path[ip_depth];
    signal input rvp_root; 
    signal input rvp_path_indexes[rvp_depth];
    signal input rvp_path[rvp_depth];

    signal input rvp_key[32]; // RVP public Ed25519 key in bytes
    signal input R8[256]; // R part of signature in bits (LSB to MSB)
    signal input S[255]; // S part of signature in bits (LSB to MSB) (first 255 bits)
    signal input PointA[4][3]; // RVP public Ed25519 key represented in base 2^85
    signal input PointR[4][3]; // R8 represented in base 2^85

    signal input plaintext[plaintext_length]; // INTRODUCE1 cell plaintext in bytes
    signal input intro_secret_hs_input[129]; // intro_secret_hs_input in bytes
    signal input client_pk[256]; // CLIENT_PK in bits (LE)
    signal input mac[256]; // MAC in bits (LE)
    var encrypted_length = plaintext_length * 8 + 256 + 256;
    signal input encrypted[encrypted_length]; // Encrypted part of the INTRODUCE1 cell in bits (LE)

    component unpack[2];
    component merkle_tree[2];
    component iseq[2];

    // Transform the RVP's root (message before signing) to bits
    signal root_bits[256];
    component n2b = Num2Bits(256);
    n2b.in <== rvp_root;
    root_bits <== n2b.out;

    // Transform kp_hs_id into bits
    signal kp_bits[256];
    unpack[0] = UnpackBytes(32);
    unpack[0].bytes <== kp_hs_id;
    kp_bits <== unpack[0].bits;

    // Transform RVP Ed25519 key into bits
    signal rvp_key_bits[256];
    unpack[1] = UnpackBytes(32);
    unpack[1].bytes <== rvp_key;
    rvp_key_bits <== unpack[1].bits;

    /*

    // Verify IP and RVP policy

    merkle_tree[0] = CheckMerkleTree(ip_depth);
    merkle_tree[0].root <== ip_root;
    merkle_tree[0].kp_bits <== kp_bits;
    merkle_tree[0].path <== ip_path;
    merkle_tree[0].path_indexes <== ip_path_indexes;
    
    merkle_tree[1] = CheckMerkleTree(rvp_depth);
    merkle_tree[1].root <== rvp_root;
    merkle_tree[1].kp_bits <== kp_bits;
    merkle_tree[1].path <== rvp_path;
    merkle_tree[1].path_indexes <== rvp_path_indexes;

    // Verify RVP's root signature with RVP key
    component verify = Ed25519Verifier(256);
    verify.msg <== root_bits;
    verify.A <== rvp_key_bits;
    verify.R8 <== R8;
    verify.S <== S;
    verify.PointA <== PointA;
    verify.PointR <== PointR;

    // Check that is 1
    // Unnecessary? In case the linear constraint 1 === verify.out is removed with constraint simplification
    0 === (verify.out - 1)*(verify.out - 1);

    // Check that Ed25519 key in P[4][3] format corresponds to the representation in bits
    component compress = PointCompress();
    compress.P <== PointA;
    iseq[0] = ForceEqualArrays(256);
    iseq[0].array1 <== rvp_key_bits;
    iseq[0].array2 <== compress.out;
    */

    // Check that the RVP key is inside the plaintext
    /*
    component check_key = CheckKeyIntroduce1(plaintext_length, start_key_byte);
    check_key.plaintext <== plaintext;
    check_key.rvp_key <== rvp_key_bits;
    */

    // Generate encryption key
    signal key[256];
    component calculate_key = GenerateKeyIntroduce1();
    calculate_key.kp_hs_id <== kp_hs_id;
    calculate_key.blinded_key <== blinded_key;
    calculate_key.intro_secret_hs_input <== intro_secret_hs_input;
    key <== calculate_key.key;
    
    // Encrypt plaintext with key
    component cipher = EncryptIntroduce1(plaintext_length);
    cipher.client_pk <== client_pk;
    cipher.plaintext <== plaintext;
    cipher.mac <== mac;
    cipher.key <== key;

    // Check that the encrypted part of the INTRODUCE1 cell and the calculated encrypted plaintext are the same
    iseq[1] = ForceEqualArrays(encrypted_length);
    iseq[1].array1 <== encrypted;
    iseq[1].array2 <== cipher.out;
}

component main {public [ip_root, encrypted]} = IP(14, 14, 512, 26);
