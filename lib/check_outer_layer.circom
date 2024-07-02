pragma circom 2.0.0;

/*
Checks that the "encrypted" field passed as an input is inside the outer layer

    "encrypted" NL encrypted-string

     [Exactly once]

      An encrypted blob containing the second layer ciphertext, whose format is
      discussed in [HS-DESC-SECOND-LAYER] below. The blob is base64 encoded
      and enclosed in -----BEGIN MESSAGE---- and ----END MESSAGE---- wrappers.

outer_length: Length of outer layer
encrypted_length: Length of the "encrypted" field
start_encrypted: Index of the first byte of the base 64 encrypted blob in the outer layer, 
i.e the index of the first byte after -----BEGIN MESSAGE---- in the outer layer
*/

template CheckOuterLayer(outer_length, encrypted_length, start_encrypted){
    signal input outer_layer[outer_length]; // Outer layer plaintext in bytes (BE)
    // "encrypted" field in bytes (BE)
    // Doesn't include the -----BEGIN MESSAGE---- and ----END MESSAGE---- wrappers
    signal input encrypted[encrypted_length];

    // Check that start_encrypted doesnt go out of bounds
    assert(start_encrypted >= 32);

    // encrypted NL in bytes (BE)
    signal field_header[10] <== [101, 110, 99, 114, 121, 112, 116, 101, 100, 10];

    // -----BEGIN MESSAGE---- in bytes (BE)
    // There are 5 "-" at the beginning, is there a typo in rend-spec?
    signal begin_message[22] <== [45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 77, 69, 83, 83, 65, 71, 69, 45, 45, 45, 45];

    // ----END MESSAGE---- in bytes (BE)
    signal end_message[19] <== [45, 45, 45, 45, 69, 78, 68, 32, 77, 69, 83, 83, 65, 71, 69, 45, 45, 45, 45];

    component iseq[encrypted_length + 51]; // encrypted_length + 10 + 22 + 19
    var j = start_encrypted - 32;
    var z = 0;

    for(var i = 0; i < 10; i++){
        iseq[z] = IsEqual();
        iseq[z].in[0] <== field_header[i];
        iseq[z].in[1] <== outer_layer[j];
        iseq[z].out === 1;
        j++;
        z++;
    }

    for(var i = 0; i < 22; i++){
        iseq[z] = IsEqual();
        iseq[z].in[0] <== begin_message[i];
        iseq[z].in[1] <== outer_layer[j];
        iseq[z].out === 1;
        j++;
        z++;
    }

    for(var i = 0; i < encrypted_length; i++){
        iseq[z] = IsEqual();
        iseq[z].in[0] <== encrypted[i];
        iseq[z].in[1] <== outer_layer[j];
        iseq[z].out === 1;
        j++;
        z++;
    }

    for(var i = 0; i < 19; i++){
        iseq[z] = IsEqual();
        iseq[z].in[0] <== end_message[i];
        iseq[z].in[1] <== outer_layer[j];
        iseq[z].out === 1;
        j++;
        z++;
    }
}