pragma circom 2.0.0;

include "circomlib/comparators.circom";
include "circomlib/bitify.circom";

// Checks if all elements in an array of bytes are in the range 0 - 255
// Done by checking if each element can be represented in 8 bits via n2b
// If element is 256 or more, n2b constraints give error
template CheckRangeBytes(size){
    signal input in[size];
    var N_BITS = 8;
    
    component n2b[size];

    for (var i = 0; i < size; i++){
        n2b[i] = Num2Bits(N_BITS);
        n2b[i].in <== in[i];
    }
}

// For the canonical representation of Ed25519 keys, each coordinate is represented in 2^85 limbs
// Verifies that all limbs are 85 bits 
template CheckRangeKeyBase85(){
    signal input in[4][3];
    var z = 0;
    component n2b[12];

    for(var i = 0; i < 4; i++){
        for (var j = 0; j < 3; j++){
            n2b[z] = Num2Bits(85);
            n2b[z].in <== in[i][j];
            z++;
        }
    }
}

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

// Transforms 32 bytes key into 2 integers that can be hashed with Poseidon
// Used for computing POLICY_COOKIE and RENDEZVOUS_COOKIE
// Since we are working in BN128, we can't directly hash with Poseidon a 32 byte number (e.g., kp_hs_id) 
template KeyToNum(){
    signal input in[32];
    signal output out[2]; // out[0] = lo, out[1] = hi

    component up = UnpackBytes(32);
    up.bytes <== in;

    component b2n[2];
    b2n[0] = Bits2Num(128);
    b2n[1] = Bits2Num(128);

    for(var i = 0; i < 128; i++){
        b2n[0].in[i] <== up.bits[i];
        b2n[1].in[i] <== up.bits[i+128];
    }

    out[0] <== b2n[0].out;
    out[1] <== b2n[1].out;
}

// a < b for 256-bit numbers given as [lo, hi] limbs (same order as KeyToNum).
// Returns 1 if a < b
// Requires every limb to be < 2^128, range-checked by the caller.
template LessThan256() {
    signal input a[2];   // a[0] = lo, a[1] = hi
    signal input b[2];
    signal output out;

    component ltHi = LessThan(128);
    ltHi.in[0] <== a[1];
    ltHi.in[1] <== b[1];

    component eqHi = IsEqual();
    eqHi.in[0] <== a[1];
    eqHi.in[1] <== b[1];

    component ltLo = LessThan(128);
    ltLo.in[0] <== a[0];
    ltLo.in[1] <== b[0];

    signal t;
    t <== eqHi.out * ltLo.out;
    out <== ltHi.out + t;   // cases are mutually exclusive, so 0 or 1
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