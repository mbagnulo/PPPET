pragma circom 2.0.0;

// Circuit to verify IP policy on HSDir

include "lib/ed25519_circom/verify.circom";
include "lib/check_merkle_tree.circom";
include "lib/check_blinded_key.circom";
include "lib/check_key_descriptor.circom";
include "lib/generate_keys.circom";

/*
start_key_byte: Index of first byte of IP key in 2nd layer of plaintext
inner_length: Length of the inner layer plaintext

Adding padding to the inner layer plaintext before passing it as an input
may be needed so it has a length multiple of 16 bytes so it can be encrypted with AES256. 
*/

template IP(depth, start_key_byte, inner_length){
    signal input kp_hs_id[32]; // Hidden service public Ed25519 key in bytes

    signal input root; // Merkle tree root
    signal input path_indexes[depth]; // Path selector to choose which direction to hash
    signal input path[depth]; // Path to the root

    signal input blinded_key[32]; // Hidden service blinded key in bytes
    signal input kp_base_85[4][3]; // Kp_hs_id in base 2^85
    signal input period_number[8]; // Period number in bytes
    signal input period_length[8]; // Period length in bytes

    signal input ip_key[32]; // IP public Ed25519 key in bytes (LE)
    signal input R8[256]; // R part of signature in bits (LSB to MSB)
    signal input S[255]; // S part of signature in bits (LSB to MSB) (first 255 bits)
    signal input PointA[4][3]; // IP public Ed25519 key represented in base 2^85
    signal input PointR[4][3]; // R8 represented in base 2^85

    signal input inner_plaintext[inner_length]; // Plaintext of inner layer
    signal input inner_salt[16]; // Salt used for generating the keys for inner layer encryption
    signal input outer_salt[16]; // Salt used for generating the keys for outer layer encryption
    signal input rev_counter[8]; // Descriptor revision counter in bytes (LE)


    // Do we need a separate salt for both encryptions? Probably yes

    /*
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

    // Transform IP key into bits
    signal ip_key_bits[256];
    component unpack2 = UnpackBytes(32);
    unpack2.bytes <== ip_key;
    ip_key_bits <== unpack2.bits;

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
    verify.A <== ip_key_bits;
    verify.R8 <== R8;
    verify.S <== S;
    verify.PointA <== PointA;
    verify.PointR <== PointR;

    1 === verify.out;
    */

    // Check that IP key is in descriptor
    component check_key = CheckKeyDescriptor(start_key_byte, inner_length);
    check_key.plaintext <== inner_plaintext;
    check_key.ip_key <== ip_key;

    // Obtain keys and IVs for encrpytion
    signal inner_key[256];
    signal inner_iv[128];
    signal outer_key[256];
    signal outer_iv[128];

    component keys_gen = GenerateKeys();
    keys_gen.kp_hs_id <== kp_hs_id;
    keys_gen.blinded_key <== blinded_key;
    keys_gen.inner_salt <== inner_salt;
    keys_gen.outer_salt <== outer_salt;
    keys_gen.rev_counter <== rev_counter;

    inner_key <== keys_gen.inner_key;
    inner_iv <== keys_gen.inner_iv;
    outer_key <== keys_gen.outer_key;
    outer_iv <== keys_gen.outer_iv;

    // Encrypt inner layer plaintext to obtain "encrypted" field
    //assert(inner_length % 16 === 0);

    // Compare calculated blob to the "encrypted" field passed as an input in base64

    /*
    Either:
    - Build the outer layer plaintext
    - Check that the correct "encrypted" field is inside the outer layer (probably this option)
    */

    // Obtain key and IV for encrypting outer text

    // Add padding and encrypt the outer layer plaintext to obtain "superencrypted" field

    // Compare calculated blob to the descriptor's header "superencrypted" field passed in base64 (public input)

}

component main {public [blinded_key]} = IP(2,80,190);