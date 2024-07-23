pragma circom 2.0.0;

include "aes256/aes_256_key_expansion.circom";
include "aes256/aes_256_ctr.circom";
include "hash_circuits/keccak/sha3_bytes.circom";
include "utils.circom";

/*
Builds and encrypts INTRODUCE1 Encrypted field

MAC: SHA3-256(k_len | k | m) --> 32 bytes
The CLIENT_PK field is the public key X (Curve25519) --> 32 bytes.

And sends, as the ENCRYPTED part of the INTRODUCE1 message:
    CLIENT_PK                [PK_PUBKEY_LEN bytes]
    ENCRYPTED_DATA           [Padded to length of plaintext]
    MAC                      [MAC_LEN bytes]

Tor applies padding to the plaintext part of the Encrypted field.
We assume that the input plaintext has already been padded

An IV of all 0s is used for encryption
*/

template EncryptIntroduce1(plaintext_length){
    signal input client_pk[256]; // CLIENT_PK in bits (LE)
    signal input plaintext[plaintext_length]; // Plaintext in bytes (LE)
    signal input mac[256]; // MAC in bits (LE)
    signal input key[256]; // Encryption key in bits (LE)

    // Transform plaintext into bits (LE)
    var bit_length = plaintext_length * 8;
    signal plaintext_bits[bit_length];
    component unpack = UnpackBytes(plaintext_length);
    unpack.bytes <== plaintext;
    plaintext_bits <== unpack.bits;

    // Create encrypt input by joining the 3 fields (bits, LE)
    var n_bits = 256 + bit_length + 256;
    signal encrypt_input[n_bits];
    component j3a = Join3Arrays(256, bit_length, 256);
    j3a.array1 <== mac;
    j3a.array2 <== plaintext_bits;
    j3a.array3 <== client_pk;
    encrypt_input <== j3a.out_array;

    // Expand encryption key
    signal ks[1920];
    component key_expand = AES256KeyExpansion();
    key_expand.key <== key;
    ks <== key_expand.w;

    // Encrypt all the bits
    signal output out[n_bits];
    // We use an IV of all 0s
    signal iv[128] <== [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    component aes = AES256CTR(n_bits);
    aes.in <== encrypt_input;
    aes.ks <== ks;
    aes.ctr <== iv;
    out <== aes.out;

}