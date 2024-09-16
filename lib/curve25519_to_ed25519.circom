pragma circom 2.0.0;

include "hash_circuits/keccak/sha3_bytes.circom";
include "ed25519_circom/binsub.circom";
include "utils.circom";
include "ed25519_circom/inversemodulo.circom";
include "circomlib/bitify.circom";
include "ed25519_circom/pointcompress.circom";
include "ed25519_circom/chunkify.circom";
include "ed25519_circom/chunkedsub.circom";
include "ed25519_circom/chunkedadd.circom";
include "ed25519_circom/modinv.circom";
include "ed25519_circom/chunkedmul.circom";

/*
Converts a Curve25519 public key into the corresponding Ed25519 public key 
The sign of the Ed25519 public key must be passed as an input
*/


// P[3] --> Bits (LE)
/*
template Dechunk(size){
    signal input chunk[size];
    signal output out[size*85];

    component n2b[size];
    var z = 0;
    for(var i = 0; i < size; i++){
        n2b[i] = Num2Bits(85);
        n2b[i].in <== chunk[i];
        for (var j = 0; j < 85; j++){
            out[z] <== n2b[i].out[j];
            z++; 
        }
    }
}
*/

// Transforms the Ed25519 public key from P[3] format to bits (LE) and adds x sign
template KeyToBits(){
    signal input sign;
    signal input chunk[3];
    signal output out[256];

    // Key in P[3] to bits
    component n2b[3];
    var z = 0;
    for(var i = 0; i < 3; i++){
        n2b[i] = Num2Bits(85);
        n2b[i].in <== chunk[i];
        for (var j = 0; j < 85; j++){
            out[z] <== n2b[i].out[j];
            z++; 
        }
    }
    // Check that the sign is 0 or 1
    sign * (sign - 1) === 0;

    // Add sign to MSB
    out[255] <== sign;
    component fq = ForceEqual();
    fq.in[0] <== out[255];
    fq.in[1] <== sign;
}


template CurveToEd(){
    signal input curve_key[32];
    signal input sign;

    signal output ed25519_key[256]; 

    // 1 in base 2^85
    signal one[3] <== [1, 0, 0];

    // Curve25519 key --> Bits (LE)
    signal curve_bits[255];
    component unpack = UnpackBytes(32);
    unpack.bytes <== curve_key;
    // Discard the MSB (always 0 on a Curve25519 public key), so Chunkify() returns only 3 chunks
    // We could perform instead mod p, but I think it is unnecessary
    for (var i = 0; i < 255; i++){
        curve_bits[i] <== unpack.bits[i];
    }

    // Convert key to base 2^85
    signal key_chunk[3];
    component chunk = Chunkify(255, 85);
    chunk.in <== curve_bits;
    key_chunk <== chunk.out;

    // u-1 % p
    signal numerator[3];
    component sub = ChunkedSub(3, 85);
    sub.a <== key_chunk;
    sub.b <== one;
    // unlike what name says, it uses base 2^85 (var base = 85 inside code)
    component mod1 = ModulusWith25519Chunked51(3);
    mod1.in <== sub.out;
    numerator <== mod1.out;

    // u+1 % p
    signal denominator[3];
    component add = ChunkedAdd(3, 2, 85);
    add.in[0] <== key_chunk;
    add.in[1] <== one;
    component mod2 = ModulusWith25519Chunked51(4);
    mod2.in <== add.out;
    denominator <== mod2.out;

    // multiplicative inverse of (u+1)
    signal denominator_inv[3];
    // again, unlike what name says actually uses base 2^85
    component inv = BigModInv51();
    inv.in <== denominator;
    denominator_inv <== inv.out;

    // Find (u-1)/(u+1) % p --> (u-1)*inv(u+1) % p
    signal chunk_result[3];
    component mul = ChunkedMul(3,3,85);
    mul.in1 <== numerator;
    mul.in2 <== denominator_inv;
    component mod3 = ModulusWith25519Chunked51(6);
    mod3.in <== mul.out;
    chunk_result <== mod3.out;

    // Convert to bits (LE) & add sign
    component k2b = KeyToBits();
    k2b.chunk <== chunk_result;
    k2b.sign <== sign;
    ed25519_key <== k2b.out;
}