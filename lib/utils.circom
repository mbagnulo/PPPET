pragma circom 2.0.0;

include "circomlib/comparators.circom";

// Check if 2 numbers are equal. If not equal, asserts error
template ForceEqual(){
    signal input in[2];

    component iseq = IsEqual();
    iseq.in[0] <== in[0];
    iseq.in[1] <== in[1];

    (1 - iseq.out) * (1 - iseq.out) === 0;
}

// Checks if 2 arrays are equal, results in error if not equal
template ForceEqualArrays(size){
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

/*
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
*/

// From https://github.com/pluto/aes-circuits/tree/main/circuits
template BytesToBits(n_bytes) {
    signal input in[n_bytes];
    signal output out[n_bytes*8];
    component num2bits[n_bytes];
    for (var i = 0; i < n_bytes; i++) {
        num2bits[i] = Num2Bits(8);
        num2bits[i].in <== in[i];
        for (var j = 7; j >=0; j--) {
            out[i*8 + j] <== num2bits[i].out[7 -j];
        }
    }
}

template BitsToBytes(n) {
    signal input in[n*8];
    signal output out[n];
    component bits2num[n];
    for (var i = 0; i < n; i++) {
        bits2num[i] = Bits2Num(8);
        for (var j = 0; j < 8; j++) {
            bits2num[i].in[7 - j] <== in[i*8 + j];
        }
        out[i] <== bits2num[i].out;
    }
}

// Bytes BE --> Bits LE
// e.g. [33, 15] --> 11110000 10000100
template BytesToBitsLE(n_bytes){
    signal input in[n_bytes];
    signal output out[n_bytes*8];
    component num2bits[n_bytes];

    var k = n_bytes - 1;
    for (var i = 0; i < n_bytes; i++) {
        num2bits[i] = Num2Bits(8);
        num2bits[i].in <== in[k];
        for (var j = 0; j < 8; j++) {
            out[i*8 + j] <== num2bits[i].out[j];
        }
        k -= 1;
    }  
}