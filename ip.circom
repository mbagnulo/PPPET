pragma circom 2.0.0;

// Circuit to verify IP policy on HSDir

include "lib/ed25519_circom/verify.circom";
include "lib/check_merkle_tree.circom";
include "lib/check_blinded_key.circom";
include "lib/check_key_descriptor.circom";
include "lib/generate_keys.circom";
include "lib/encrypt_descriptor.circom";
include "lib/compare_descriptors.circom";
include "lib/check_outer_layer.circom";

/*
start_key_byte: Index of first byte of IP key in 2nd layer of plaintext
inner_length: Length of the inner layer plaintext

Adding padding to the inner layer plaintext before passing it as an input
may be needed so it has a length multiple of 16 bytes so it can be encrypted with AES256. 
*/

template IP(depth, start_key_byte, inner_length, outer_length, start_encrypted_byte){
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

    // Padding bytes necessary before encrypting outer layer
    var padding = calculate_padding(outer_length);

    // Lengths of "encrypted" and "superencrypted" fields
    var encrypted_length = 4 * ((inner_length + 2) \ 3);
    var superencrypted_length = 4 * ((outer_length + padding + 2) \ 3);

    signal input inner_plaintext[inner_length]; // Plaintext of inner layer
    signal input outer_plaintext[outer_length]; // Plaintext of outer layer
    signal input inner_salt[16]; // Salt used for generating the keys for inner layer encryption
    signal input outer_salt[16]; // Salt used for generating the keys for outer layer encryption
    signal input rev_counter[8]; // Descriptor revision counter in bytes (LE)
    signal input encrypted[encrypted_length]; // "encrypted" field of outer layer in BE bytes (Base64 -> ASCII)
    signal input superencrypted[superencrypted_length]; // "superencrypted" field of descriptor header in BE bytes (Base64 -> ASCII)

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
    
    // Check P[4][3] representation of Ed25519 key corresponds to the bytes representation
    component compress = PointCompress(); // P[4][3] -> Bits (little endian)
    compress.P <== PointA;
    component iseq_key = IsEqualArrays(256);
    iseq_key.array1 <== rvp_key_bits;
    iseq_key.array2 <== compress.out;

    // Verify signature
    component verify = Ed25519Verifier(256);
    verify.msg <== root_bits;
    verify.A <== ip_key_bits;
    verify.R8 <== R8;
    verify.S <== S;
    verify.PointA <== PointA;
    verify.PointR <== PointR;

    1 === verify.out;

    // Check that IP key is in descriptor
    component check_key = CheckKeyDescriptor(start_key_byte, inner_length);
    check_key.plaintext <== inner_plaintext;
    check_key.ip_key <== ip_key_bits;

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
    assert(inner_length % 16 == 0);
    var n_bits = inner_length * 8;
    signal encrypted_inner_layer[n_bits];
    component encrypt_inner = EncryptInnerLayer(inner_length);
    encrypt_inner.plaintext <== inner_plaintext;
    encrypt_inner.key <== inner_key;
    encrypt_inner.iv <== inner_iv;
    encrypted_inner_layer <== encrypt_inner.encrypted_plaintext;

    // Compare calculated blob to the "encrypted" field passed as an input in base64
    component comp_desc_1 = CompareDescriptor(inner_length);
    comp_desc_1.b64_field <== encrypted;
    comp_desc_1.enc_result <== encrypted_inner_layer;

    // Check that the "encrypted" field in the outer layer is correct
    component check_outer = CheckOuterLayer(outer_length, encrypted_length, start_encrypted_byte);
    check_outer.outer_layer <== outer_plaintext;
    check_outer.encrypted <== encrypted;

    // Add padding and encrypt the outer layer plaintext to obtain "superencrypted" field
    var n_bits_2 = (outer_length + padding) * 8;
    signal encrypted_outer_layer[n_bits_2];
    component encrypt_outer = EncryptOuterLayer(outer_length, padding);
    encrypt_outer.plaintext <== outer_plaintext;
    encrypt_outer.key <== outer_key;
    encrypt_outer.iv <== outer_iv;
    encrypted_outer_layer <== encrypt_outer.encrypted_plaintext;

    // Compare calculated blob to the descriptor's header "superencrypted" field passed in base64 (public input)
    component comp_desc_2 = CompareDescriptor(outer_length + padding);
    comp_desc_2.b64_field <== superencrypted;
    comp_desc_2.enc_result <== encrypted_outer_layer;
}

component main {public [blinded_key, superencrypted]} = IP(2,80,1008, 4752, 1532);