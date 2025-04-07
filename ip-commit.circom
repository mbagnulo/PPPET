pragma circom 2.0.0;

include "lib/ed25519_circom/pointcompress.circom";
include "lib/check_merkle_tree.circom";
include "lib/check_key_introduce.circom";
include "lib/generate_keys_introduce1.circom";
include "lib/encrypt_introduce1.circom";
include "lib/circomlib/eddsaposeidon.circom";
include "lib/check_proof_commitment.circom";

/* 
    Verifies IP's and RVP's policies in the IP
    - ip_depth & rvp_depth: Depths of IP and RVP Merkle Tree
    - plaintext_lengt: Length of INTRODUCE1 plaintext
    - start_key_byte: Index of first byte of the RVP key in the INTRODUCE1 cell plaintext

    Client must calculate RVP's Ed25519 key out of circuit

    In this version, the client verifies RVP's signature with a BabyJubJub key REDACT THIS
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

    signal input plaintext[plaintext_length]; // INTRODUCE1 cell plaintext in bytes
    signal input intro_secret_hs_input[129]; // intro_secret_hs_input in bytes
    signal input encrypted[plaintext_length*8]; // Encrypted plaintext in bits

    // RVP Babyjubjub key & signature
    signal input rvp_x;
    signal input rvp_y;
    signal input S;
    signal input R8x;
    signal input R8y;

    // Commitment and nonce to link with RVP's proof
    signal input proof_commitment;
    signal input nonce;

    // Transform the RVP's root (message before signing) to bits
    signal root_bits[256];
    component n2b = Num2Bits(256);
    n2b.in <== rvp_root;
    root_bits <== n2b.out;

    // Transform kp_hs_id into bits
    signal kp_bits[256];
    component unpack = UnpackBytes(32);
    unpack.bytes <== kp_hs_id;
    kp_bits <== unpack.bits;

    // Transform RVP Ed25519 key into bits
    signal rvp_key_bits[256];
    component unpack_rvp = UnpackBytes(32);
    unpack_rvp.bytes <== rvp_key;
    rvp_key_bits <== unpack_rvp.bits;

    // Verify IP and RVP policy
    component ip_mt = CheckMerkleTree(ip_depth);
    ip_mt.root <== ip_root;
    ip_mt.kp_bits <== kp_bits;
    ip_mt.path <== ip_path;
    ip_mt.path_indexes <== ip_path_indexes;
    
    component rvp_mt = CheckMerkleTree(rvp_depth);
    rvp_mt.root <== rvp_root;
    rvp_mt.kp_bits <== kp_bits;
    rvp_mt.path <== rvp_path;
    rvp_mt.path_indexes <== rvp_path_indexes;
    
    // Check that the RVP key is inside the plaintext
    component check_key = CheckKeyIntroduce1(plaintext_length, start_key_byte);
    check_key.plaintext <== plaintext;
    check_key.rvp_key <== rvp_key_bits;

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
    component iseq_enc = ForceEqualArrays(plaintext_length*8);
    iseq_enc.array1 <== encrypted;
    iseq_enc.array2 <== cipher.out;

    // Verify RVP's signature with BabyJubjub
    component verify = EdDSAPoseidonVerifier();
    verify.enabled <== 1;
    verify.Ax <== rvp_x;
    verify.Ay <== rvp_y;
    verify.S <== S;
    verify.R8x <== R8x;
    verify.R8y <== R8y;
    verify.M <== rvp_root;

    // Calculate hash and compare
    component check_commitment = CheckProofCommitment();
    check_commitment.commitment <== proof_commitment;
    check_commitment.rvp_ed_key <== rvp_key;
    check_commitment.rvp_jubjub_x <== rvp_x;
    check_commitment.rvp_jubjub_y <== rvp_y;
    check_commitment.nonce <== nonce;
}

component main {public [ip_root, encrypted, proof_commitment]} = IP(14, 14, 192, 26);
