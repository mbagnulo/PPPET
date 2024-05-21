pragma circom 2.0.0;

include "lib/ed25519_circom/pointcompress.circom";
include "lib/hash_circuits/keccak/sha3_bytes.circom";
include "lib/utils.circom";
include "lib/circomlib/comparators.circom";



template Main(){
    signal input kp_bytes[32]; // Kp_hs_id in bytes
    signal input kp_base_85[4][3]; // Kp_hs_id in base 2^85
    signal input period_number[8]; // period number as an array of 8 bytes
    signal input period_length[8]; // period length as an array of 8 bytes
    // signal input blinded_key ¿bytes o bits?

    signal h[32];
    signal h_bits[256];
    signal h_clamped[255];
    signal kp_bits_1[256];
    signal kp_bits_2[256];

    component unpack = UnpackBytes(32); // Bytes -> Bits (little endian)
    component compress = PointCompress(); // P[4][3] -> Bits (little endian)
    component eq_arrays = IsEqualArrays(256);

    // Check that kp_bytes = kp_base_85
    unpack.bytes <== kp_bytes;
    kp_bits_1 <== unpack.bits;
    compress.P <== kp_base_85;
    kp_bits_2 <== compress.out;

    eq_arrays.array1 <== kp_bits_1;
    eq_arrays.array2 <== kp_bits_2;

    //"Derive temporary signing key\0" encoded with ASCII
    signal BLIND_STRING[29] <== [68, 101, 114, 105, 118, 101, 32, 116, 101, 109, 112, 111, 114, 97, 114, 121, 32, 115, 105, 103, 110, 105, 110, 103, 32, 107, 101, 121, 0];

    //"(1511...2202, 4631...5960)" encoded with ASCII
    signal ED22519_BASEPOINT[158] <== [40, 49, 53, 49, 49, 50, 50, 50, 49, 51, 52, 57, 53, 51, 53, 52, 48, 48, 55, 55, 50, 53, 48, 49, 49, 53, 49, 52, 48, 57, 53, 56, 56, 53, 51, 49, 53, 49, 49, 52, 53, 52, 48, 49, 50, 54, 57, 51, 48, 52, 49, 56, 53, 55, 50, 48, 54, 48, 52, 54, 49, 49, 51, 50, 56, 51, 57, 52, 57, 56, 52, 55, 55, 54, 50, 50, 48, 50, 44, 32, 52, 54, 51, 49, 54, 56, 51, 53, 54, 57, 52, 57, 50, 54, 52, 55, 56, 49, 54, 57, 52, 50, 56, 51, 57, 52, 48, 48, 51, 52, 55, 53, 49, 54, 51, 49, 52, 49, 51, 48, 55, 57, 57, 51, 56, 54, 54, 50, 53, 54, 50, 50, 53, 54, 49, 53, 55, 56, 51, 48, 51, 51, 54, 48, 51, 49, 54, 53, 50, 53, 49, 56, 53, 53, 57, 54, 48, 41];

    //"key-blind" encoded with ASCII
    signal KEYBLIND_STRING[9] <== [107, 101, 121, 45, 98, 108, 105, 110, 100];

    component fuse_arrays = FuseAllArrays(29,32,158,9,8,8);
    fuse_arrays.array1 <== BLIND_STRING;
    fuse_arrays.array2 <== kp_bytes;
    fuse_arrays.array3 <== ED22519_BASEPOINT;
    fuse_arrays.array4 <== KEYBLIND_STRING;
    fuse_arrays.array5 <== period_number;
    fuse_arrays.array6 <== period_length;

    signal hash_input[244];
    hash_input <== fuse_arrays.out_array;

    // Find h = H("BLIND_STRING" | Kp_hs_id | ...)
    component sha3 = SHA3_256_bytes(244);
    sha3.inp_bytes <== hash_input;
    h <== sha3.out_bytes;

    component unpack_2 = UnpackBytes(32);
    unpack_2.bytes <== h;
    h_bits <== unpack.bits;

    // Perform clamping on h
    component clamp = Clamping();
    clamp.h <== h_bits;
    h_clamped <== clamp.h_clamped;
    
    // Perform scalar multiplication


    // Compare scalar multiplication result with input blinded key


    

}

component main {public [period_number,period_length]}= Main();