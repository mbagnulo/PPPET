pragma circom 2.0.0;

include "ed25519_circom/pointcompress.circom";
include "ed25519_circom/scalarmul.circom";
include "hash_circuits/keccak/sha3_bytes.circom";
include "utils.circom";
include "circomlib/comparators.circom";

/*
    Checks that input blinded key is properly derived from kp_hs_id

    h = SHA3_256(BLIND_STRING | kp_hs_id | s | B | N)
    BLIND_STRING = "Derive temporary signing key" | INT_1(0)
    N = "key-blind" | INT_8(period-number) | INT_8(period_length)
    B = "(1511[...]2202, 4631[...]5960)"
    Optional secret s is omitted
    
    Apply claming to h according to Ed25519 specification
    blinded_key = h*A
*/

// Performs clamping to the blinding factor according to Ed25519 documentation
template Clamping(){
    signal input h[256]; // h is in little endian
    signal output out[255];

    component isz[3];
    component iseq[251];

    // Bits 1 (LSB), 2, 3 ==> 0 
    for (var i = 0; i<3; i++){
        isz[i] = IsZero();
        out[i] <== 0;
        isz[i].in <== out[i];
        (isz[i].out - 1) * (isz[i].out - 1) === 0;
    }

    // Copy bits
    var j = 0;
    for (var i = 3; i < 254; i++){
        iseq[j] = ForceEqual();
        out[i] <== h[i];
        iseq[j].in[0] <== h[i];
        iseq[j].in[1] <== out[i];
        j++;
    }

    // Bit 255 ==> 1
    out[254] <== 1;
    0 === (out[254] - 1)*(out[254] - 1);
}


template CreateBKHashInput(){
    signal input kp_hs_id[32];
    signal input period_number[8];
    signal input period_length[8];
    signal output out[244];

    //"Derive temporary signing key\0" encoded with ASCII
    var BLIND_STRING[29] = [68, 101, 114, 105, 118, 101, 32, 116, 101, 109, 112, 111, 114, 97, 114, 121, 32, 115, 105, 103, 110, 105, 110, 103, 32, 107, 101, 121, 0];
    //"(1511...2202, 4631...5960)" encoded with ASCII
    var ED25519_BASEPOINT[158] = [40, 49, 53, 49, 49, 50, 50, 50, 49, 51, 52, 57, 53, 51, 53, 52, 48, 48, 55, 55, 50, 53, 48, 49, 49, 53, 49, 52, 48, 57, 53, 56, 56, 53, 51, 49, 53, 49, 49, 52, 53, 52, 48, 49, 50, 54, 57, 51, 48, 52, 49, 56, 53, 55, 50, 48, 54, 48, 52, 54, 49, 49, 51, 50, 56, 51, 57, 52, 57, 56, 52, 55, 55, 54, 50, 50, 48, 50, 44, 32, 52, 54, 51, 49, 54, 56, 51, 53, 54, 57, 52, 57, 50, 54, 52, 55, 56, 49, 54, 57, 52, 50, 56, 51, 57, 52, 48, 48, 51, 52, 55, 53, 49, 54, 51, 49, 52, 49, 51, 48, 55, 57, 57, 51, 56, 54, 54, 50, 53, 54, 50, 50, 53, 54, 49, 53, 55, 56, 51, 48, 51, 51, 54, 48, 51, 49, 54, 53, 50, 53, 49, 56, 53, 53, 57, 54, 48, 41];
    //"key-blind" encoded with ASCII
    var KEYBLIND_STRING[9] = [107, 101, 121, 45, 98, 108, 105, 110, 100];

    // Obtain the input to the hash
    //component fuse_arrays = Join6Arrays(29,32,158,9,8,8)
    component iseq[29 + 32 + 158 + 9 + 8 + 8];

    // Join arrays + enforce equality with quadratic constraint
    component j6a = Join6Arrays(29, 32, 158, 9, 8, 8);
    j6a.array1 <== BLIND_STRING;
    j6a.array2 <== kp_hs_id;
    j6a.array3 <== ED25519_BASEPOINT;
    j6a.array4 <== KEYBLIND_STRING;
    j6a.array5 <== period_number;
    j6a.array6 <== period_length;

    out <== j6a.out_array;
}

template GenerateBlindedKey(){
    signal input kp_hs_id[32];
    signal input kp_base_85[4][3];
    signal input blinded_key[32];
    signal input period_number[8];
    signal input period_length[8];

    signal output out[32];
    
    // Check that kp_hs_id === kp_base_85
    component compress_1 = PointCompress();
    component pack_1 = PackBytes(32);
    compress_1.P <== kp_base_85;
    pack_1.bits <== compress_1.out;

    component iseq_1 = ForceEqualArrays(32);
    iseq_1.array1 <== kp_hs_id;
    iseq_1.array2 <== pack_1.bytes;

    component preimage = CreateBKHashInput();
    preimage.kp_hs_id <== kp_hs_id;
    preimage.period_number <== period_number;
    preimage.period_length <== period_length;

    // Find h = H("BLIND_STRING" | Kp_hs_id | ...) in bits
    component sha3 = SHA3_256_bytes(244);
    component unpack = UnpackBytes(32);
    sha3.inp_bytes <== preimage.out;
    unpack.bytes <== sha3.out_bytes;

    // Perform clamping on h
    component clamp = Clamping();
    clamp.h <== unpack.bits;
    
    // Perform scalar multiplication
    component scalarmul = ScalarMul();
    scalarmul.s <== clamp.out;
    scalarmul.P <== kp_base_85;

    // Result to bytes
    component compress_2 = PointCompress();
    component pack_2 = PackBytes(32);
    compress_2.P <== scalarmul.sP;
    pack_2.bits <== compress_2.out;

    out <== pack_2.bytes;
}