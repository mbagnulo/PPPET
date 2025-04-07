pragma circom 2.0.0;

include "ed25519_circom/scalarmul.circom";
include "ed25519_circom/pointcompress.circom";
include "hash_circuits/sha2/sha512/sha512_hash_bytes.circom";

/* Calculates the public Ed25519 key from the secret key 
   The process is as follows:
    1- Find h = SHA512(secret key) and keep the first 32 bytes of the output (h[:32])
    2- Apply clamping to h[:32] --> h_clamped
    3- Perform h_clamped * G, where G is the Ed25519 base point
*/
// -----------------------------------------------------

template SkToPkEd(){
    signal input in[32];

    signal output out[32];

    component sha = Sha512_hash_bytes_digest(32);
    sha.inp_bytes <== in;

    component up = UnpackBytes(32);
    for(var i = 0; i < 32; i++){
        up.bytes[i] <== sha.hash_bytes[i];
    }

    // Base point
    var G[4][3] = [[6836562328990639286768922, 21231440843933962135602345, 10097852978535018773096760],
                    [7737125245533626718119512, 23211375736600880154358579, 30948500982134506872478105],
                    [1, 0, 0],
                    [20943500354259764865654179, 24722277920680796426601402, 31289658119428895172835987]
                  ];

    component scalarmul = ScalarMul();
    // We first discard the last 32 bytes
    // Then, we apply clamping:
    // 1. Bits 1 (lsb), 2 and 3 --> 0
    // 2. Bit 255 --> 1
    // 3. Bit 256 (msb) --> 0, we discard it

    // Clear first 3 bits
    for(var i = 0; i < 3; i++){
        scalarmul.s[i] <== up.bits[i] * 0;
    }
    // Copy rest of bits
    for(var i = 3; i < 254; i++){
        scalarmul.s[i] <== up.bits[i];
    }
    // Bit 255 OR 1
    scalarmul.s[254] <== up.bits[254] + 1 - up.bits[254] * 1;
    scalarmul.P <== G;

    component compress = PointCompress();
    component pack = PackBytes(32);

    compress.P <== scalarmul.sP;
    pack.bits <== compress.out;

    out <== pack.bytes;
}

    /*
    Okay, so
    UnpackBytes takes a byte sequence in LE (i.e., the last byte is the MSB) and transforms it to bits
    I'll represent the most significant bit with **, and the least significant bit with __

    Usually, to transform from LE bytes to LE bits you do:
    [A, B, C] --> [C_bin, B_bin, A_bin]  e.g., [32, 15] --> *0*0001111 0010000_0_
    With UnpackBytes:
    [A, B, C] --> [A_bin_le, B_bin_le, C_bin_le] e.g., [32, 15] --> _0_0000100 1111000*0*

    When passing the input to ScalarMul, we discard the msb, i.e the last bit
    
    Therefore, when performing clamping to the output of UnpackBytes:
     - Set most significant bit (256) to 0 --> b[255] &= 0
     - Set bit 255 to 1 --> b[254] |= 1
     - Set the first/lsb 3 bits to 0 -->  b[0], b[1], b[2] &= 0
     */