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

template CreateBKHashInput(){
    signal input kp_hs_id[32];
    signal input period_number[8];
    signal input period_length[8];
    signal output out[244];

    //"Derive temporary signing key\0" encoded with ASCII
    var BLIND_STRING[29] = [68, 101, 114, 105, 118, 101, 32, 116, 101, 109, 112, 111, 114, 97, 114, 121, 32, 115, 105, 103, 110, 105, 110, 103, 32, 107, 101, 121, 0];
    //"(1511...2202, 4631...5960)" encoded with ASCII
    var ED22519_BASEPOINT[158] = [40, 49, 53, 49, 49, 50, 50, 50, 49, 51, 52, 57, 53, 51, 53, 52, 48, 48, 55, 55, 50, 53, 48, 49, 49, 53, 49, 52, 48, 57, 53, 56, 56, 53, 51, 49, 53, 49, 49, 52, 53, 52, 48, 49, 50, 54, 57, 51, 48, 52, 49, 56, 53, 55, 50, 48, 54, 48, 52, 54, 49, 49, 51, 50, 56, 51, 57, 52, 57, 56, 52, 55, 55, 54, 50, 50, 48, 50, 44, 32, 52, 54, 51, 49, 54, 56, 51, 53, 54, 57, 52, 57, 50, 54, 52, 55, 56, 49, 54, 57, 52, 50, 56, 51, 57, 52, 48, 48, 51, 52, 55, 53, 49, 54, 51, 49, 52, 49, 51, 48, 55, 57, 57, 51, 56, 54, 54, 50, 53, 54, 50, 50, 53, 54, 49, 53, 55, 56, 51, 48, 51, 51, 54, 48, 51, 49, 54, 53, 50, 53, 49, 56, 53, 53, 57, 54, 48, 41];
    //"key-blind" encoded with ASCII
    var KEYBLIND_STRING[9] = [107, 101, 121, 45, 98, 108, 105, 110, 100];

    // Obtain the input to the hash
    //component fuse_arrays = Join6Arrays(29,32,158,9,8,8)
    component iseq[29 + 32 + 158 + 9 + 8 + 8];

    // Join arrays + enforce equality with quadratic constraint
    var j = 0;
    for(var i = 0; i < 29; i++){
        iseq[j] = ForceEqual();
        out[j] <== BLIND_STRING[i];
        iseq[j].in[0] <== BLIND_STRING[i];
        iseq[j].in[1] <== out[j];
        j++;
    }
    for(var i = 0; i < 32; i++){
        iseq[j] = ForceEqual();
        out[j] <== kp_hs_id[i];
        iseq[j].in[0] <== kp_hs_id[i];
        iseq[j].in[1] <== out[j];
        j++;
    }
    for(var i = 0; i < 158; i++){
        iseq[j] = ForceEqual();
        out[j] <== ED22519_BASEPOINT[i];
        iseq[j].in[0] <== ED22519_BASEPOINT[i];
        iseq[j].in[1] <== out[j];
        j++;
    }
    for(var i = 0; i < 9; i++){
        iseq[j] = ForceEqual();
        out[j] <== KEYBLIND_STRING[i];
        iseq[j].in[0] <== KEYBLIND_STRING[i];
        iseq[j].in[1] <== out[j];
        j++;
    }
    for(var i = 0; i < 8; i++){
        iseq[j] = ForceEqual();
        out[j] <== period_number[i];
        iseq[j].in[0] <== period_number[i];
        iseq[j].in[1] <== out[j];
        j++;
    }
    for(var i = 0; i < 8; i++){
        iseq[j] = ForceEqual();
        out[j] <== period_length[i];
        iseq[j].in[0] <== period_length[i];
        iseq[j].in[1] <== out[j];
        j++;
    }
}

template CheckBlindedKey(){
    signal input kp_bytes[32];
    signal input kp_bits[256];
    signal input kp_base_85[4][3];
    signal input blinded_key[32];
    signal input period_number[8];
    signal input period_length[8];
    
    signal h[32];
    signal h_bits[256];
    signal h_clamped[255];
    signal kp_bits_1[256];
    signal kp_bits_2[256];

    component compress[2]; // P[4][3] -> Bits (little endian)
    component iseq[2];
    component unpack[2];

    // Check that kp_bits === kp_base_85
    // We don't check that kp_bits === kp_bytes because we calculate kp_bits from
    // kp_bytes in the main circuit, so we already know
    
    compress[0] = PointCompress();
    compress[0].P <== kp_base_85;
    iseq[0] = IsEqualArrays(256);
    iseq[0].array1 <== kp_bits;
    iseq[0].array2 <== compress[0].out;

    component preimage = CreateBKHashInput();
    preimage.kp_hs_id <== kp_bytes;
    preimage.period_number <== period_number;
    preimage.period_length <== period_length;

    // Find h = H("BLIND_STRING" | Kp_hs_id | ...)
    component sha3 = SHA3_256_bytes(244);
    sha3.inp_bytes <== preimage.out;
    h <== sha3.out_bytes;

    unpack[0] = UnpackBytes(32);
    unpack[0].bytes <== h;
    h_bits <== unpack[0].bits;

    // Perform clamping on h
    component clamp = Clamping();
    clamp.h <== h_bits;
    h_clamped <== clamp.h_clamped;
    
    // Perform scalar multiplication
    component scalarmul = ScalarMul();
    scalarmul.s <== clamp.h_clamped;
    scalarmul.P <== kp_base_85;

    // Result to bits
    compress[1] = PointCompress();
    compress[1].P <== scalarmul.sP;
    
    // Input blinded key to bits
    unpack[1] = UnpackBytes(32);
    unpack[1].bytes <== blinded_key;

    // Compare input blinded key to the one we've just calculated
    // Generates an error if they are not equal
    iseq[1] = IsEqualArrays(256);
    iseq[1].array1 <== compress[1].out;
    iseq[1].array2 <== unpack[1].bits;
}

// component main {public [bkey_bytes, period_number, period_length]}= CheckBlindedKey();