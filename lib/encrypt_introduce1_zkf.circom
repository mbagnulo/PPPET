pragma circom 2.0.0;

include "chacha20/chacha20-bits.circom";
include "utils.circom";

template EncryptIntroduce1_ZKF(length){
    signal input plaintext[length];
    signal input key[256]; // LE

    var n_blocks = length/4;

    component cypher = ChaCha20(n_blocks, 32);

    // Tor uses an IV of all 0s for encryption...
    var nonce[3][32] = [
                    [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                    [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                    [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
                ];
    
    var counter[32] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];

    // Plaintext to BE bits
    component bytes2bits = BytesToBits(length);
    bytes2bits.in <== plaintext;

    cypher.nonce <== nonce;
    cypher.counter <== counter;

    var k = 0;
    for(var i = 0; i < n_blocks; i++){
        for(var j = 0; j < 32; j++){
            cypher.in[i][j] <== bytes2bits.out[k];
            k++;
        }
    }

    // Input key is in LE (output from Num2Bits), but we need to pass it in BE
    k = 255;
    for(var i = 0; i < 8; i++){
        for(var j = 0; j < 32; j++){
            cypher.key[i][j] <== key[k];
            k--;
        }
    }

    signal output out[n_blocks][4];
    component bits2bytes[n_blocks];
    k = 0;
    
    // Output to bytes
    for(var i = 0; i < n_blocks; i++){
        bits2bytes[i] = BitsToBytes(4);
        bits2bytes[i].in <== cypher.out[i];
        out[i] <== bits2bytes[i].out;
    }
}