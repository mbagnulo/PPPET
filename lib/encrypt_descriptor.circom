pragma circom 2.0.0;

include "aes256/aes_256_key_expansion.circom";
include "aes256/aes_256_ctr.circom";
include "utils.circom";

/* 
Encrypts inner layer plaintext. No padding is added, input must have a byte length
multiple of 16 (we check with an assert in ip.circom)
*/
template EncryptInnerLayer(plaintext_length){
    signal input key[256];
    signal input iv[128];
    signal input plaintext[plaintext_length];

    var n_bits = plaintext_length * 8;
    signal output encrypted_plaintext[n_bits];
    
    // Expand key
    signal ks[1920];
    component key_expand = AES256KeyExpansion();
    key_expand.key <== key;
    ks <== key_expand.w;

    // Plaintext in BE bytes --> Plaintext in LE bits
    signal plaintext_bits[n_bits];
    component unpack = UnpackBytes_BE_to_LE(plaintext_length);
    unpack.bytes <== plaintext;
    plaintext_bits <== unpack.bits;

    // Encrypt plaintext
    component aes = AES256CTR(n_bits);
    aes.in <== plaintext_bits;
    aes.ks <== ks;
    aes.ctr <== iv;
    encrypted_plaintext <== aes.out;
    
}