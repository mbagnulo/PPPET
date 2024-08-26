pragma circom 2.0.0;

include "aes256/aes_256_key_expansion.circom";
include "aes256/aes_256_ctr.circom";
include "utils.circom";

/*
Calculates padding (in bytes) needed for encrypting outer layer. Outer layer must be padded before encrypting
until the length is equal to the closest 10k byte multiple.
*/
function calculate_padding(length){
    var padding;
    var max_length = 10000;

    while (length > max_length){
        max_length = max_length + 10000;
    }

    padding = max_length - length;
    return padding;
}

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

// Adds padding to the outer layer plaintext before encrypting
template AddPadding(plaintext_length, padding){
    signal input plaintext[plaintext_length];
    signal output out[plaintext_length + padding];

    // Copy plaintext to output array
    component iseq[plaintext_length];
    component isz[padding];
    var j = 0;
    for(var i = 0; i < plaintext_length; i++){
        iseq[i] = ForceEqual();
        out[j] <== plaintext[i];
        iseq[i].in[0] <== plaintext[i];
        iseq[i].in[1] <== out[j];
        j++;
    }

    for(var i = 0; i < padding; i++){
        isz[i] = IsZero();
        out[j] <== 0;
        isz[i].in <== out[j];
        (isz[i].out - 1)*(isz[i].out - 1) === 0;
        j++;
    }
}

/* 
Encrypts outer layer plaintext
padding: Bytes of padding needed. Calculated with calculate_padding() in ip.circom
*/
template EncryptOuterLayer(plaintext_length, padding){
    signal input key[256];
    signal input iv[128];
    signal input plaintext[plaintext_length];
    
    // Expand key
    signal ks[1920];
    component key_expand = AES256KeyExpansion();
    key_expand.key <== key;
    ks <== key_expand.w;

    var n_bits = (plaintext_length + padding) * 8;

    // Add padding
    signal padded_plaintext[plaintext_length + padding];
    component add_padding = AddPadding(plaintext_length, padding);
    add_padding.plaintext <== plaintext;
    padded_plaintext <== add_padding.out;

    // Plaintext in BE bytes --> Plaintext in LE bits
    signal plaintext_bits[n_bits];
    component unpack = UnpackBytes_BE_to_LE(plaintext_length + padding);
    unpack.bytes <== padded_plaintext;
    plaintext_bits <== unpack.bits;

    // Encrypt plaintext
    signal output encrypted_plaintext[n_bits];
    component aes = AES256CTR(n_bits);
    aes.in <== plaintext_bits;
    aes.ks <== ks;
    aes.ctr <== iv;
    encrypted_plaintext <== aes.out;
}