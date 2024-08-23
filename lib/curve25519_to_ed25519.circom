pragma circom 2.0.0;

include "hash_circuits/keccak/sha3_bytes.circom";
include "ed25519_circom/binsub.circom";
//include "ed25519_circom/modulus.circom";
include "ed25519_circom/inversemodulo.circom";
include "circomlib/bitify.circom";
include "ed25519_circom/pointcompress.circom";
include "ed25519_circom/chunkify.circom";
include "ed25519_circom/chunkedsub.circom";
include "ed25519_circom/chunkedadd.circom";
include "ed25519_circom/modinv.circom";
include "ed25519_circom/chunkedmul.circom";
//include "ed25519_circom/verify.circom";


template Main(){
    signal input curve_key[32];

    //signal output ed25519_key[255]; 

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

    // (u-1)/(u+1) % p --> (u-1)*inv(u+1) % p
    signal result[3];
    component mul = ChunkedMul(3,3,85);
    mul.in1 <== numerator;
    mul.in2 <== denominator_inv;
    component mod3 = ModulusWith25519Chunked51(6);
    mod3.in <== mul.out;
    result <== mod3.out;

    // Convert to bits


    // Place sign (x bit, 0 or 1)


    // Ed25519 key --> Bytes (LE)

}

component main = Main();