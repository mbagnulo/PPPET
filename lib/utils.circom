pragma circom 2.0.0;

//include "../lib/circomlib/comparators.circom";
include "circomlib/comparators.circom";
include "hash_circuits/keccak/keccak-p.circom";


// Performs clamping to the blinding factor according to Ed25519 documentation
template Clamping(){
    signal input h[256]; // h is in little endian
    signal output h_clamped[255];

    component isz[255];

    // Bits 1 (LSB), 2, 3 ==> 0 
    for (var i = 0; i<3; i++){
        isz[i] = IsZero();
        h_clamped[i] <== 0;
        isz[i].in <== h_clamped[i];
        isz[i].out === 1;
    }

    // Copy bits
    for (var i = 3; i < 254; i++){
        isz[i] = IsZero();
        h_clamped[i] <== h[i];
        h[i] - h_clamped[i] ==> isz[i].in;
        isz[i].out === 1;
    }

    // Bit 255 ==> 1
    h_clamped[254] <== h[254] + 1 - h[254]*1; // OR 1
}


// Compares if 2 arrays are equal
template IsEqualArrays(size){
    signal input array1[size];
    signal input array2[size];

    component isz[size];

    for (var i = 0; i < size; i++){
        isz[i] = IsZero();
        array1[i] - array2[i] ==> isz[i].in;
        isz[i].out === 1;
    }
}

template Join2Arrays(size1, size2){
    signal input array1[size1];
    signal input array2[size2];
    signal output out_array[size1 + size2];

    // Check that arrays are copied properly with a restriction
    component isz[size1 + size2];

    var j = 0;
    for(var i = 0; i < size1; i++){
        isz[j] = IsZero();
        out_array[j] <== array1[i];
        out_array[j] - array1[i] ==> isz[j].in;
        isz[j].out === 1;
        j++;
    }

    for(var i = 0; i < size2; i++){
        isz[j] = IsZero();
        out_array[j] <== array2[i];
        out_array[j] - array2[i] ==> isz[j].in;
        isz[j].out === 1;
        j++;
    }
}

template Join3Arrays(size1, size2, size3){
    signal input array1[size1];
    signal input array2[size2];
    signal input array3[size3];
    signal output out_array[size1 + size2 + size3];

    // Check that arrays are copied properly with a restriction
    component isz[size1 + size2 + size3];

    var j = 0;
    for(var i = 0; i < size1; i++){
        isz[j] = IsZero();
        out_array[j] <== array1[i];
        out_array[j] - array1[i] ==> isz[j].in;
        isz[j].out === 1;
        j++;
    }

    for(var i = 0; i < size2; i++){
        isz[j] = IsZero();
        out_array[j] <== array2[i];
        out_array[j] - array2[i] ==> isz[j].in;
        isz[j].out === 1;
        j++;
    }

    for(var i = 0; i < size3; i++){
        isz[j] = IsZero();
        out_array[j] <== array3[i];
        out_array[j] - array3[i] ==> isz[j].in;
        isz[j].out === 1;
        j++;
    }
}


// Fuses 6 arrays
template FuseAllArrays(size1, size2, size3, size4, size5, size6){
    signal input array1[size1];
    signal input array2[size2];
    signal input array3[size3];
    signal input array4[size4];
    signal input array5[size5];
    signal input array6[size6];
    signal output out_array[size1 + size2 + size3 + size4 + size5 + size6];

    // We also check that the array element is copied with a restriction
    component isz[size1 + size2 + size3 + size4 + size5 + size6];

    var j = 0;
    for(var i = 0; i < size1; i++){
        isz[j] = IsZero();
        out_array[j] <== array1[i];
        out_array[j] - array1[i] ==> isz[j].in;
        isz[j].out === 1;
        j++;
    }

    for(var i = 0; i < size2; i++){
        isz[j] = IsZero();
        out_array[j] <== array2[i];
        out_array[j] - array2[i] ==> isz[j].in;
        isz[j].out === 1;
        j++;
    }

    for(var i = 0; i < size3; i++){
        isz[j] = IsZero();
        out_array[j] <== array3[i];
        out_array[j] - array3[i] ==> isz[j].in;
        isz[j].out === 1;
        j++;
    }

    for(var i = 0; i < size4; i++){
        isz[j] = IsZero();
        out_array[j] <== array4[i];
        out_array[j] - array4[i] ==> isz[j].in;
        isz[j].out === 1;
        j++;
    }

    for(var i = 0; i < size5; i++){
        isz[j] = IsZero();
        out_array[j] <== array5[i];
        out_array[j] - array5[i] ==> isz[j].in;
        isz[j].out === 1;
        j++;
    }

    for(var i = 0; i < size6; i++){
        isz[j] = IsZero();
        out_array[j] <== array6[i];
        out_array[j] - array6[i] ==> isz[j].in;
        isz[j].out === 1;
        j++;
    }
}

// Separate 2 arrays
template Separate2Arrays(size1, size2){
    signal input in_array[size1 + size2];
    signal output out_array1[size1];
    signal output out_array2[size2];

    component isz[size1 + size2];
    var j = 0;
    for(var i = 0; i < size1; i++){
        isz[j] = IsZero();
        out_array1[i] <== in_array[j];
        out_array1[i] - in_array[j] ==> isz[j].in;
        isz[j].out === 1;
        j++;
    }

    for(var i = 0; i < size2; i++){
        isz[j] = IsZero();
        out_array2[i] <== in_array[j];
        out_array2[i] - in_array[j] ==> isz[j].in;
        isz[j].out === 1;
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