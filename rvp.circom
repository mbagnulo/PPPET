pragma circom 2.0.0;

include "lib/ed25519_circom/verify.circom";
include "lib/check_merkle_tree.circom";
include "lib/check_blinded_key.circom";
include "lib/check_key_introduce.circom";
include "lib/generate_keys_introduce1.circom";
include "lib/encrypt_introduce1.circom";

// start_key_byte: Index of first byte of the RVP key in the INTRODUCE1 cell plaintext
template RVP(depth, plaintext_length, start_key_byte){
    signal input kp_hs_id[32]; // Hidden service public Ed25519 key in bytes

    signal input root; // Merkle tree root
    signal input path_indexes[depth]; // Path selector to choose which direction to hash
    signal input path[depth]; // Path to the root

    signal input blinded_key[32]; // Hidden service blinded key in bytes
    signal input kp_base_85[4][3]; // Kp_hs_id in base 2^85
    signal input period_number[8]; // Period number in bytes
    signal input period_length[8]; // Period length in bytes

    signal input rvp_key[32]; // RVP public Ed25519 key in bytes (LE)
    signal input R8[256]; // R part of signature in bits (LSB to MSB)
    signal input S[255]; // S part of signature in bits (LSB to MSB) (first 255 bits)
    signal input PointA[4][3]; // RVP public Ed25519 key represented in base 2^85
    signal input PointR[4][3]; // R8 represented in base 2^85

    signal input plaintext[plaintext_length]; // INTRODUCE1 cell plaintext in bytes (BE)
    signal input intro_secret_hs_input[129]; // intro_secret_hs_input in bytes (LE)
    signal input client_pk[256]; // CLIENT_PK in bits (LE)
    signal input mac[256]; // MAC in bits (LE)
    var encrypted_length = plaintext_length * 8 + 256 + 256;
    signal input encrypted[encrypted_length]; // Encrypted part of the INTRODUCE1 cell in bits (LE)


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

    // Transform RVP Ed25519 key into bits
    signal rvp_key_bits[256];
    component unpack2 = UnpackBytes(32);
    unpack2.bytes <== rvp_key;
    rvp_key_bits <== unpack2.bits;

    // Check that kp_hs_id is on IP allow list
    component merkle_tree = CheckMerkleTree(depth);
    merkle_tree.root <== root;
    merkle_tree.kp_bits <== kp_bits;
    merkle_tree.path <== path;
    merkle_tree.path_indexes <== path_indexes;

    // Verify root signature with RVP key
    component verify = Ed25519Verifier(256);
    verify.msg <== root_bits;
    verify.A <== rvp_key_bits;
    verify.R8 <== R8;
    verify.S <== S;
    verify.PointA <== PointA;
    verify.PointR <== PointR;

    1 === verify.out;

    // Check that Ed25519 key in P[4][3] format corresponds to the representation in bits
    component compress = PointCompress(); // P[4][3] -> Bits (little endian)
    compress.P <== PointA;
    component iseq_key = IsEqualArrays(256);
    iseq_key.array1 <== rvp_key_bits;
    iseq_key.array2 <== compress.out;

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
    cipher.client_pk <== client_pk;
    cipher.plaintext <== plaintext;
    cipher.mac <== mac;
    cipher.key <== key;

    // Check that the encrypted part of the INTRODUCE1 cell and the calculated encrypted plaintext are the same
    component iseq = IsEqualArrays(encrypted_length);
    iseq.array1 <== encrypted;
    iseq.array2 <== cipher.out;
}

component main {public [encrypted]} = RVP(2, 192, 26);
