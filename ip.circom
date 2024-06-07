pragma circom 2.0.0;

include "lib/ed25519_circom/verify.circom";

template IP(msg_length){
    signal input msg[msg_length]; // Message before signing in bits
    signal input ip_key[256]; // IP public Ed25519 key in bits (LSB to MSB)
    signal input R8[256]; // R part of signature in bits (LSB to MSB)
    signal input S[255]; // S part of signature in bits (LSB to MSB) (first 255 bits)

    signal input PointA[4][3]; // IP public Ed25519 key represented in base 2^85
    signal input PointR[4][3]; // R8 represented in base 2^85

    // Maybe pass the inputs in bytes and not bits?

    // Remove msg as input and use merkle tree root

    component verify = Ed25519Verifier(msg_length);
    verify.msg <== msg;
    verify.A <== ip_key;
    verify.R8 <== R8;
    verify.S <== S;
    verify.PointA <== PointA;
    verify.PointR <== PointR;

    1 === verify.out;

}

component main {public [ip_key]} = IP(16);