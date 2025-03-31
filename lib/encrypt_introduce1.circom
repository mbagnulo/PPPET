pragma circom 2.0.0;

include "aes256/aes_256_key_expansion.circom";
include "aes256/aes_256_ctr.circom";
include "hash_circuits/keccak/sha3_bytes.circom";
include "utils.circom";

/*
ENCRYPTED part of the INTRODUCE1 message:
    CLIENT_PK                [PK_PUBKEY_LEN bytes]
    ENCRYPTED_DATA           [Padded to length of plaintext]
    MAC                      [MAC_LEN bytes]

Encrypts the plaintext, generating ENCRYPTED_DATA. The plaintext is the only part that is actually encrypted.

We assume that the plaintext has already been padded to the appropiate length. 
Tor C client requires that header length + plaintext length >= 246
Additionally, Electron's Lab AES-256 implementation requires plaintext's length to be a multiple of 16.

Tor uses an IV of all 0s for encryption
*/

template EncryptIntroduce1(plaintext_length){
    signal input plaintext[plaintext_length]; // Plaintext in bytes
    signal input key[256]; // Encryption key in bits

    var n_bits = plaintext_length * 8;
    signal output out[n_bits];

    // Transform plaintext into bits
    signal plaintext_bits[n_bits];
    component b2b = BytesToBits(plaintext_length);
    b2b.in <== plaintext;
    plaintext_bits <== b2b.out;

    // Expand encryption key
    signal ks[1920];
    component key_expand = AES256KeyExpansion();
    key_expand.key <== key;
    ks <== key_expand.w;

    // Encrypt all the bits
    // Tor uses an IV of all 0s for this part
    signal iv[128] <== [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    component aes = AES256CTR(n_bits);
    aes.in <== plaintext_bits;
    aes.ks <== ks;
    aes.ctr <== iv;
    out <== aes.out;

}