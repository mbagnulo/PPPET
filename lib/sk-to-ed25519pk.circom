pragma circom 2.0.0;

include "ed25519_circom/scalarmul.circom";
include "ed25519_circom/pointcompress.circom";
include "utils_bytes.circom";
 
/* Calculates kp_hs_id from ks_hs_id

Tor doesn't store the initial seed. ks_hs_id is in 64 bytes expanded format --> ks_hs_id = SHA512(seed)

We'll pass as input the first 32 bytes of ks_hs_id, and perform the rest of the process:
    1- Apply clamping to input according to Ed25519 specification
    2- Perform input_clamped * G, where G is the Ed25519 base point
*/

template SkToPkEd(){
    signal input in[32];

    signal output out[32];

    component up = UnpackBytes(32);
    up.bytes <== in;

    // Base point
    var G[4][3] = [[6836562328990639286768922, 21231440843933962135602345, 10097852978535018773096760],
                    [7737125245533626718119512, 23211375736600880154358579, 30948500982134506872478105],
                    [1, 0, 0],
                    [20943500354259764865654179, 24722277920680796426601402, 31289658119428895172835987]
                  ];

    component scalarmul = ScalarMul();
    // Apply clamping:

    // 1. Clear first 3 bits
    for(var i = 0; i < 3; i++){
        scalarmul.s[i] <== up.bits[i] * 0;
    }
    // 2. Copy rest of bits
    for(var i = 3; i < 254; i++){
        scalarmul.s[i] <== up.bits[i];
    }
    // 3. Bit 255 OR 1, we discard bit 256
    scalarmul.s[254] <== up.bits[254] + 1 - up.bits[254] * 1;
    scalarmul.P <== G;

    component compress = PointCompress();
    component pack = PackBytes(32);

    compress.P <== scalarmul.sP;
    pack.bits <== compress.out;

    out <== pack.bytes;
}