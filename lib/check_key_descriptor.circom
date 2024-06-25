pragma circom 2.0.0;

include "utils.circom";
include "circomlib/comparators.circom";
include "base64/base64.circom";
/*
Checks that the IP key is inside the inner layer plaintext of the descriptor 

Plaintext input is assumed to be in Big Endian and decoded with ASCII.

We are assuming that the key is written in the plaintext in little endian as its the
standard for Curve25519 (If possible check if this is right)
*/

// Check that the proper field ("onion-key" SP "ntor" SP) is before the key
template CheckField(start_key_byte, plaintext_length, field_length){
    signal input plaintext[plaintext_length];
    // "onion-key SP ntor SP" in BE with ASCII
    signal key_field[15] <== [111, 110, 105, 111, 110, 45, 107, 101, 121, 32, 110, 116, 111, 114, 32];

    // Check that parameter value is correct
    assert(field_length == 15);
    // Check that the index doesnt go out of bounds
    assert((start_key_byte - 15) >= 0);

    component iseq[field_length];
    var j = start_key_byte - 15;
    for(var i = 0; i < 15; i++){
        iseq[i] = IsEqual();
        iseq[i].in[0] <== key_field[i];
        iseq[i].in[1] <== plaintext[j];
        /* Linear constraint, but does it matter? We just want to check that the field is
        correct, which is public info anyways. Shouldn't add any complexity to the final equations regardless*/
        iseq[i].out === 1;
        j++;
    }
}

// Retrieves the IP Base64 key (BE) from second layer plaintext
// start_key_byte: Index of first byte of the IP key in plaintext
template RetrieveKey(start_key_byte, plaintext_length){
    signal input plaintext[plaintext_length];
    signal output ip_key_base64[44]; // 32 bytes -> 44 base64 chars

    var j = start_key_byte;
    for(var i = 0; i < 44; i++){
        // Necessary to add constraints here? Would be linear
        ip_key_base64[i] <== plaintext[j];
        j++;
    }
}

template CheckKeyDescriptor(start_key_byte, plaintext_length){
    signal input plaintext[plaintext_length];
    signal input ip_key[32]; // IP key in bytes (LE)

    // Check that the key is in the proper field ("onion-key" SP "ntor" SP key NL)
    component check_field = CheckField(start_key_byte, plaintext_length, 15);
    check_field.plaintext <== plaintext;

    // Retrieve IP key (Base64 in ASCII)
    signal ip_key_base64[44];
    component get_key = RetrieveKey(start_key_byte, plaintext_length);
    get_key.plaintext <== plaintext;
    ip_key_base64 <== get_key.ip_key_base64;

    // Decode IP key from Base64 to bytes
    // As said before we are assuming that the key is written in the plaintext in LE, so
    // no addition conversion is needed
    signal plaintext_key[32];
    component base64 = Base64Decode(32);
    base64.in <== ip_key_base64;
    plaintext_key <== base64.out;

    // Compare IP key and key found in plaintext
    component iseq = IsEqualArrays(32);
    iseq.array1 <== ip_key;
    iseq.array2 <== plaintext_key;
}

//component main = CheckKeyDescriptor(80,190);