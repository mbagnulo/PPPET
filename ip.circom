pragma circom 2.0.0;

include "lib/ed25519_circom/verify.circom";
include "lib/hash_circuits/keccak/sha3_bytes.circom";

template IP(){
    signal input root; // Merkle tree root
    signal input ip_key[256]; // IP public Ed25519 key in bits (LSB to MSB)
    signal input R8[256]; // R part of signature in bits (LSB to MSB)
    signal input S[255]; // S part of signature in bits (LSB to MSB) (first 255 bits)

    signal input PointA[4][3]; // IP public Ed25519 key represented in base 2^85
    signal input PointR[4][3]; // R8 represented in base 2^85

    // Transform the root (message signed) to bits
    signal root_bits[256];
    component n2b = Num2Bits(256);
    n2b.in <== root;
    root_bits <== n2b.out;
    
    component verify = Ed25519Verifier(256);
    verify.msg <== root_bits;
    verify.A <== ip_key;
    verify.R8 <== R8;
    verify.S <== S;
    verify.PointA <== PointA;
    verify.PointR <== PointR;

    1 === verify.out;
    log(verify.out);
}

component main = IP();