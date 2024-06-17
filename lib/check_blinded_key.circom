pragma circom 2.0.0;

include "ed25519_circom/pointcompress.circom";
include "ed25519_circom/scalarmul.circom";
include "hash_circuits/keccak/sha3_bytes.circom";
include "utils.circom";
include "circomlib/comparators.circom";



template CheckBlindedKey(){
    signal input kp_bytes[32];
    signal input kp_bits[256];
    signal input kp_base_85[4][3];
    signal input bkey_bytes[32];
    signal input period_number[8];
    signal input period_length[8];
    
    signal h[32];
    signal h_bits[256];
    signal h_clamped[255];
    signal kp_bits_1[256];
    signal kp_bits_2[256];
    signal bkey_base_85[4][3];

    component compress = PointCompress(); // P[4][3] -> Bits (little endian)
    component eq_arrays = IsEqualArrays(256);

    // Check that kp_bits === kp_base_85
    // We don't check that kp_bits === kp_bytes because we calculate kp_bits from
    // kp_bytes in the main circuit, so we already know

    compress.P <== kp_base_85;
    kp_bits_2 <== compress.out;

    eq_arrays.array1 <== kp_bits;
    eq_arrays.array2 <== kp_bits_2;

    //"Derive temporary signing key\0" encoded with ASCII and in LE
    signal BLIND_STRING[29] <== [0, 121, 101, 107, 32, 103, 110, 105, 110, 103, 105, 115, 32, 121, 114, 97, 114, 111, 112, 109, 101, 116, 32, 101, 118, 105, 114, 101, 68];

    //"(1511...2202, 4631...5960)" encoded with ASCII and in LE
    signal ED22519_BASEPOINT[158] <== [41, 48, 54, 57, 53, 53, 56, 49, 53, 50, 53, 54, 49, 51, 48, 54, 51, 51, 48, 51, 56, 55, 53, 49, 54, 53, 50, 50, 54, 53, 50, 54, 54, 56, 51, 57, 57, 55, 48, 51, 49, 52, 49, 51, 54, 49, 53, 55, 52, 51, 48, 48, 52, 57, 51, 56, 50, 52, 57, 54, 49, 56, 55, 52, 54, 50, 57, 52, 57, 54, 53, 51, 56, 54, 49, 51, 54, 52, 32, 44, 50, 48, 50, 50, 54, 55, 55, 52, 56, 57, 52, 57, 51, 56, 50, 51, 49, 49, 54, 52, 48, 54, 48, 50, 55, 53, 56, 49, 52, 48, 51, 57, 54, 50, 49, 48, 52, 53, 52, 49, 49, 53, 49, 51, 53, 56, 56, 53, 57, 48, 52, 49, 53, 49, 49, 48, 53, 50, 55, 55, 48, 48, 52, 53, 51, 53, 57, 52, 51, 49, 50, 50, 50, 49, 49, 53, 49, 40];

    //"key-blind" encoded with ASCII and in LE
    signal KEYBLIND_STRING[9] <== [100, 110, 105, 108, 98, 45, 121, 101, 107];

    // Obtain the input to the hash (in LE)
    component fuse_arrays = FuseAllArrays(8,8,9,158,32,29);

    /*    
    h = H(BLIND_STRING | A | s | B | N)
    BLIND_STRING = "Derive temporary signing key" | INT_1(0)
    N = "key-blind" | INT_8(period-number) | INT_8(period_length)
    B = "(1511[...]2202, 4631[...]5960)"
    */

    fuse_arrays.array1 <== period_length;
    fuse_arrays.array2 <== period_number;
    fuse_arrays.array3 <== KEYBLIND_STRING;
    fuse_arrays.array4 <== ED22519_BASEPOINT;
    fuse_arrays.array5 <== kp_bytes;
    fuse_arrays.array6 <== BLIND_STRING;

    signal hash_input[244];
    hash_input <== fuse_arrays.out_array;

    // Find h = H("BLIND_STRING" | Kp_hs_id | ...)
    component sha3 = SHA3_256_bytes(244);
    sha3.inp_bytes <== hash_input;
    h <== sha3.out_bytes;

    component unpack_2 = UnpackBytes(32);
    unpack_2.bytes <== h;
    h_bits <== unpack_2.bits;

    // Perform clamping on h
    component clamp = Clamping();
    clamp.h <== h_bits;
    h_clamped <== clamp.h_clamped;
    
    // Perform scalar multiplication
    component scalarmul = ScalarMul();
    scalarmul.s <== h_clamped;
    scalarmul.P <== kp_base_85;
    bkey_base_85 <== scalarmul.sP;

    // Compare scalar multiplication result with input blinded key
    component unpack_3 = UnpackBytes(32);
    component compress_2 = PointCompress();
    signal bkey_bits_1[256];
    signal bkey_bits_2[256];

    compress_2.P <== bkey_base_85;
    bkey_bits_1 <== compress_2.out;
    
    unpack_3.bytes <== bkey_bytes;
    bkey_bits_2 <== unpack_3.bits;

    component eq_arrays_2 = IsEqualArrays(256);
    eq_arrays_2.array1 <== bkey_bits_1;
    eq_arrays_2.array2 <== bkey_bits_2;
}

// component main {public [bkey_bytes, period_number, period_length]}= CheckBlindedKey();