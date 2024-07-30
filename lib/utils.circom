pragma circom 2.0.0;

//include "../lib/circomlib/comparators.circom";
include "circomlib/comparators.circom";
include "hash_circuits/keccak/keccak-p.circom";

// Check if 2 numbers are equal. If not equal, asserts error
template ForceEqual(){
    signal input in[2];

    component iseq = IsEqual();
    iseq.in[0] <== in[0];
    iseq.in[1] <== in[1];

    (1 - iseq.out) * (1 - iseq.out) === 0;
}

// Performs clamping to the blinding factor according to Ed25519 documentation
template Clamping(){
    signal input h[256]; // h is in little endian
    signal output h_clamped[255];

    component isz[3];
    component iseq[251];

    // Bits 1 (LSB), 2, 3 ==> 0 
    for (var i = 0; i<3; i++){
        isz[i] = IsZero();
        h_clamped[i] <== 0;
        isz[i].in <== h_clamped[i];
        (isz[i].out - 1) * (isz[i].out - 1) === 0;
    }

    // Copy bits
    var j = 0;
    for (var i = 3; i < 254; i++){
        iseq[j] = ForceEqual();
        h_clamped[i] <== h[i];
        iseq[j].in[0] <== h[i];
        iseq[j].in[1] <== h_clamped[i];
        j++;
    }

    // Bit 255 ==> 1
    h_clamped[254] <== h[254] + 1 - h[254]*1; // OR 1
}


// Compares if 2 arrays are equal
template IsEqualArrays(size){
    signal input array1[size];
    signal input array2[size];

    component iseq[size];

    for (var i = 0; i < size; i++){
        iseq[i] = ForceEqual();
        iseq[i].in[0] <== array1[i];
        iseq[i].in[1] <== array2[i];
    }
}

template Join2Arrays(size1, size2){
    signal input array1[size1];
    signal input array2[size2];
    signal output out_array[size1 + size2];

    // Check that arrays are copied properly with a restriction
    component iseq[size1 + size2];

    var j = 0;
    for(var i = 0; i < size1; i++){
        iseq[j] = ForceEqual();
        out_array[j] <== array1[i];
        iseq[j].in[0] <== array1[i];
        iseq[j].in[1] <== out_array[j];
        j++;
    }

    for(var i = 0; i < size2; i++){
        iseq[j] = ForceEqual();
        out_array[j] <== array2[i];
        iseq[j].in[0] <== array2[i];
        iseq[j].in[1] <== out_array[j];
        j++;
    }
}

template Join3Arrays(size1, size2, size3){
    signal input array1[size1];
    signal input array2[size2];
    signal input array3[size3];
    signal output out_array[size1 + size2 + size3];

    // Check that arrays are copied properly with a restriction
    component iseq[size1 + size2 + size3];

    var j = 0;
    for(var i = 0; i < size1; i++){
        iseq[j] = ForceEqual();
        out_array[j] <== array1[i];
        iseq[j].in[0] <== array1[i];
        iseq[j].in[1] <== out_array[j];
        j++;
    }

    for(var i = 0; i < size2; i++){
        iseq[j] = ForceEqual();
        out_array[j] <== array2[i];
        iseq[j].in[0] <== array2[i];
        iseq[j].in[1] <== out_array[j];
        j++;
    }

    for(var i = 0; i < size3; i++){
        iseq[j] = ForceEqual();
        out_array[j] <== array3[i];
        iseq[j].in[0] <== array3[i];
        iseq[j].in[1] <== out_array[j];
        j++;
    }
}


// Joins 6 arrays
template Join6Arrays(size1, size2, size3, size4, size5, size6){
    signal input array1[size1];
    signal input array2[size2];
    signal input array3[size3];
    signal input array4[size4];
    signal input array5[size5];
    signal input array6[size6];
    signal output out_array[size1 + size2 + size3 + size4 + size5 + size6];

    // We also check that the array element is copied with a restriction
    component iseq[size1 + size2 + size3 + size4 + size5 + size6];

    var j = 0;
    for(var i = 0; i < size1; i++){
        iseq[j] = ForceEqual();
        out_array[j] <== array1[i];
        iseq[j].in[0] <== array1[i];
        iseq[j].in[1] <== out_array[j];
        j++;
    }

    for(var i = 0; i < size2; i++){
        iseq[j] = ForceEqual();
        out_array[j] <== array2[i];
        iseq[j].in[0] <== array2[i];
        iseq[j].in[1] <== out_array[j];
        j++;
    }

    for(var i = 0; i < size3; i++){
        iseq[j] = ForceEqual();
        out_array[j] <== array3[i];
        iseq[j].in[0] <== array3[i];
        iseq[j].in[1] <== out_array[j];
        j++;
    }

    for(var i = 0; i < size4; i++){
        iseq[j] = ForceEqual();
        out_array[j] <== array4[i];
        iseq[j].in[0] <== array4[i];
        iseq[j].in[1] <== out_array[j];
        j++;
    }

    for(var i = 0; i < size5; i++){
        iseq[j] = ForceEqual();
        out_array[j] <== array5[i];
        iseq[j].in[0] <== array5[i];
        iseq[j].in[1] <== out_array[j];
        j++;
    }

    for(var i = 0; i < size6; i++){
        iseq[j] = ForceEqual();
        out_array[j] <== array6[i];
        iseq[j].in[0] <== array6[i];
        iseq[j].in[1] <== out_array[j];
        j++;
    }
}

// Separate 2 arrays
template Separate2Arrays(size1, size2){
    signal input in_array[size1 + size2];
    signal output out_array1[size1];
    signal output out_array2[size2];

    component iseq[size1 + size2];
    var j = 0;
    for(var i = 0; i < size1; i++){
        iseq[j] = ForceEqual();
        out_array1[i] <== in_array[j];
        iseq[j].in[0] <== in_array[j];
        iseq[j].in[1] <== out_array1[i];
        j++;
    }

    for(var i = 0; i < size2; i++){
        iseq[j] = ForceEqual();
        out_array2[i] <== in_array[j];
        iseq[j].in[0] <== in_array[j];
        iseq[j].in[1] <== out_array2[i];
        j++;
    }
}

// Takes a byte sequence in BE and transforms it to a LE bit sequence
// Based on UnpackBytes() from hash_circuits
template UnpackBytes_BE_to_LE(n) {
  signal input  bytes[n];
  signal output bits[8*n];

  component tobits[n];
  var z = n - 1;
  for(var j=0; j<n; j++) {
    tobits[j] = ToBits(8);
    tobits[j].inp <== bytes[z];
    z--;
    for(var i=0; i<8; i++) {
      tobits[j].out[i] ==> bits[ j*8 + i ];
    }
  }
}