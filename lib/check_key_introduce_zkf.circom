pragma circom 2.0.0;

include "circomlib/bitify.circom";
include "hash_circuits/keccak/sha3_bytes.circom"; // For PackBytes()
include "utils.circom";

/* Slightly adapted to be used with IP_ZKF()*/

template CheckKeyIntroduce1_ZKF(length, start_key_byte){
    signal input key_x;
    signal input key_y;
    signal input plaintext[length];

    // Coordenates to bytes
    component n2b_x = Num2Bits(256);
    component pack_x = PackBytes(32);
    n2b_x.in <== key_x;
    pack_x.bits <== n2b_x.out;

    component n2b_y = Num2Bits(256);
    component pack_y = PackBytes(32);
    n2b_y.in <== key_y;
    pack_y.bits <== n2b_y.out;

    // Check that ONION_KEY_TYPE is 1 ([1])
    component feq1 = ForceEqual();
    feq1.in[0] <== plaintext[start_key_byte - 3];
    feq1.in[1] <== 1;

    // Check that ONION_KEY_LEN is 64 ([0,64])
    component isz = IsZero();
    isz.in <== plaintext[start_key_byte - 2];
    (isz.out - 1)*(isz.out - 1) === 0;

    component feq2 = ForceEqual();
    feq2.in[0] <== plaintext[start_key_byte - 1];
    feq2.in[1] <== 64;

    // Verify that both keys are in the plaintext
    component feq[64];
    var j = start_key_byte;
    for(var i = 0; i < 32; i++){
        feq[i] = ForceEqual();
        feq[i].in[0] <== pack_x.bytes[i];
        feq[i].in[1] <== plaintext[j];
        j++;
    }
    var k = 0;
    for(var i = 32; i < 64; i++){
        feq[i] = ForceEqual();
        feq[i].in[0] <== pack_y.bytes[k];
        feq[i].in[1] <== plaintext[j];
        j++;
        k++;
    }
}

