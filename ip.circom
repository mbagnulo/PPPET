pragma circom 2.0.0;

// Circuit to verify IP policy on HSDir

include "lib/ed25519_circom/verify.circom";
include "lib/check_merkle_tree.circom";
include "lib/check_blinded_key.circom";

template IP(depth){
    signal input kp_hs_id[32]; // Hidden service public Ed25519 key in bytes

    signal input root; // Merkle tree root
    signal input path_indexes[depth]; // Path selector to choose which direction to hash
    signal input path[depth]; // Path to the root

    signal input blinded_key[32]; // Hidden service blinded key in bytes
    signal input kp_base_85[4][3]; // Kp_hs_id in base 2^85
    signal input period_number[8]; // Period number in bytes
    signal input period_length[8]; // Period length in bytes

    signal input ip_key[256]; // IP public Ed25519 key in bits (LSB to MSB)
    signal input R8[256]; // R part of signature in bits (LSB to MSB)
    signal input S[255]; // S part of signature in bits (LSB to MSB) (first 255 bits)
    signal input PointA[4][3]; // IP public Ed25519 key represented in base 2^85
    signal input PointR[4][3]; // R8 represented in base 2^85

    // Transform the root (message before signing) to bits
    signal root_bits[256];
    component n2b = Num2Bits(256);
    n2b.in <== root;
    root_bits <== n2b.out;

    // Transform kp_hs_id into bits
    signal kp_bits[256];
    component unpack = UnpackBytes(32);
    unpack.bytes <== kp_hs_id;
    kp_bits <== unpack.bits;

    // Check that kp_hs_id is on IP allow list
    component merkle_tree = CheckMerkleTree(depth);
    merkle_tree.root <== root;
    merkle_tree.kp_bits <== kp_bits;
    merkle_tree.path <== path;
    merkle_tree.path_indexes <== path_indexes;

    // Check that input blinded key corresponds to the one calculated with kp_hs_id
    component check_bkey = CheckBlindedKey();
    check_bkey.kp_bytes <== kp_hs_id;
    check_bkey.kp_bits <== kp_bits;
    check_bkey.kp_base_85 <== kp_base_85;
    check_bkey.bkey_bytes <== blinded_key;
    check_bkey.period_number <== period_number;
    check_bkey.period_length <== period_length;   
    
    // Verify signature
    component verify = Ed25519Verifier(256);
    verify.msg <== root_bits;
    verify.A <== ip_key;
    verify.R8 <== R8;
    verify.S <== S;
    verify.PointA <== PointA;
    verify.PointR <== PointR;

    1 === verify.out;
}

component main {public [blinded_key, period_number, period_length]} = IP(2);