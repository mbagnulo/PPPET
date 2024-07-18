pragma circom 2.0.0;

include "utils.circom";
include "circomlib/comparators.circom";

/*
Checks that the hidden service key is inside the INTRODUCE1 cell encrypted plaintext

The plaintext has the structure:
    RENDEZVOUS_COOKIE[20 bytes]
    ...
    ONION_KEY_TYPE[1 bytes]
    ONION_KEY_LEN[2 bytes]
    ONION_KEY[ONION_KEY_LEN bytes]
    ...
    PAD

Where ONION_KEY_TYPE is always 01 and ONION_KEY_LEN is 32 bytes

We assume that the plaintext has already been padded to the appropiate length
for encrypting with AES256
*/

template RetrieveKeyIntroduce1(length, start_key_byte){
    signal input plaintext[length];
    signal output out[32];

    var j = start_key_byte;
    for(var i = 0; i < 32; i++){
        out[i] <== plaintext[j];
        out[i] - plaintext[j] === 0; // necessary?
        j++;
    }
}

// start_key_byte: First byte of the key in the ONION_KEY field
template CheckKeyIntroduce1(length, start_key_byte){
    signal input plaintext[length]; // Plaintext in bytes (BE)
    signal input rvp_key[32]; // RVP key in bytes (LE)

    // Retreive key from plaintext
    signal rvp_key_text[32];
    component ret_key = RetrieveKeyIntroduce1(length, start_key_byte);
    ret_key.plaintext <== plaintext;
    rvp_key_text <== ret_key.out;

    // Check that ONION_KEY_TYPE is 1 ([1])
    component iseq1 = IsEqual();
    iseq1.in[0] <== plaintext[start_key_byte - 3];
    iseq1.in[1] <== 1;
    iseq1.out === 1;

    // Check that ONION_KEY_LEN is 32 ([0,32])
    component isz = IsZero();
    isz.in <== plaintext[start_key_byte - 2];
    isz.out === 1;

    component iseq2 = IsEqual();
    iseq2.in[0] <== plaintext[start_key_byte - 1];
    iseq2.in[1] <== 32;
    iseq2.out === 1;

    // Check that the correct rvp_key is inside the plaintext
    // We assume that the RVP key is written in LE in the plaintext, so no additional steps are required
    // (would be nice to verify, but shouldn't affect the constraint number anyways)

    component iseq_arrays = IsEqualArrays(32);
    iseq_arrays.array1 <== rvp_key;
    iseq_arrays.array2 <== rvp_key_text;
}