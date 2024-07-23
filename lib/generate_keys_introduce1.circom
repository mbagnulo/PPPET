pragma circom 2.0.0;

include "hash_circuits/keccak/sha3_bytes.circom";
include "utils.circom";

// Generates encryption keys for INTRODUCE1 cell

/*
The PROTOID for this variant is "tor-hs-ntor-curve25519-sha3-256-1". We also use the following tweak values:

      t_hsenc    = PROTOID | ":hs_key_extract"
      t_hsverify = PROTOID | ":hs_verify"
      t_hsmac    = PROTOID | ":hs_mac"
      m_hsexpand = PROTOID | ":hs_key_expand"

To make an INTRODUCE1 message, the client must know a public encryption key B for the hidden service on this introduction circuit. The client generates a single-use keypair:

x,X = KEYGEN()

and computes:

             intro_secret_hs_input = EXP(B,x) | AUTH_KEY | X | B | PROTOID
             info = m_hsexpand | N_hs_subcred
             hs_keys = KDF(intro_secret_hs_input | t_hsenc | info, S_KEY_LEN+MAC_LEN)
             ENC_KEY = hs_keys[0:S_KEY_LEN]
             MAC_KEY = hs_keys[S_KEY_LEN:S_KEY_LEN+MAC_KEY_LEN]

   and sends, as the ENCRYPTED part of the INTRODUCE1 message:

          CLIENT_PK                [PK_PUBKEY_LEN bytes]
          ENCRYPTED_DATA           [Padded to length of plaintext]
          MAC                      [MAC_LEN bytes]

N_hs_subcred = H("subcredential" | N_hs_cred | blinded-public-key).
N_hs_cred = H("credential" | public-identity-key)

We can't calculate intro_secret_hs_input in Circom, so we will take it as an input. We will use
N_hs_subcred as the part which links the key generation with the hidden service.
*/

// Generates the "info" parameter
// info = m_hsexpand | N_hs_subcred

template GenerateInfo(){
    signal input blinded_key[32];
    signal input kp_hs_id[32];

    // "tor-hs-ntor-curve25519-sha3-256-1:hs_key_expand" in bytes (LE)
    signal m_hsexpand[47] <== [100, 110, 97, 112, 120, 101, 95, 121, 101, 107, 95, 115, 104, 58, 49, 45, 54, 53, 50, 45, 51, 97, 104, 115, 45, 57, 49, 53, 53, 50, 101, 118, 114, 117, 99, 45, 114, 111, 116, 110, 45, 115, 104, 45, 114, 111, 116];

    // "credential" and "subcredential" converted to bytes (LE) with ASCII
    signal credential[10] <== [108, 97, 105, 116, 110, 101, 100, 101, 114, 99];
    signal subcredential[13] <== [108, 97, 105, 116, 110, 101, 100, 101, 114, 99, 98, 117, 115];

    // Find N_hs_cred
    signal n_hs_cred[32];
    component j2a = Join2Arrays(32,10);
    j2a.array1 <== kp_hs_id;
    j2a.array2 <== credential;
    
    component sha3_1 = SHA3_256_bytes(42);
    sha3_1.inp_bytes <== j2a.out_array;
    n_hs_cred <== sha3_1.out_bytes;

    // Find N_hs_subcred
    signal n_hs_subcred[32];
    component j3a = Join3Arrays(32, 32, 13);
    j3a.array1 <== blinded_key;
    j3a.array2 <== n_hs_cred;
    j3a.array3 <== subcredential;

    component sha3_2 = SHA3_256_bytes(77);
    sha3_2.inp_bytes <== j3a.out_array;
    n_hs_subcred <== sha3_2.out_bytes;

    // Calculate info = m_hsexpand | N_hs_subcred (LE)
    signal output info[79];

    component j2a_2 = Join2Arrays(32,47);
    j2a_2.array1 <== n_hs_subcred;
    j2a_2.array2 <== m_hsexpand;
    info <== j2a_2.out_array;
}

template GenerateKeyIntroduce1(){
    signal input kp_hs_id[32];
    signal input blinded_key[32];
    // intro_secret_hs_input = EXP(B,x) | AUTH_KEY | X | B | "tor-hs-ntor-curve25519-sha3-256-1"
    var length = 129; // 32 + 32 + 32 + 33
    signal input intro_secret_hs_input[length]; // intro_secret_hs_input in bytes (LE)

    // "tor-hs-ntor-curve25519-sha3-256-1:hs_key_extract" in bytes (LE)
    signal t_hsenc[48] <== [116, 99, 97, 114, 116, 120, 101, 95, 121, 101, 107, 95, 115, 104, 58, 49, 45, 54, 53, 50, 45, 51, 97, 104, 115, 45, 57, 49, 53, 53, 50, 101, 118, 114, 117, 99, 45, 114, 111, 116, 110, 45, 115, 104, 45, 114, 111, 116];

    // Generate "info" parameter
    signal info[79];
    component get_info = GenerateInfo();
    get_info.blinded_key <== blinded_key;
    get_info.kp_hs_id <== kp_hs_id;
    info <== get_info.info;

    // Generate input for keys = KDF(...) (LE)
    var kdf_length = 79 + 48 + length;
    signal kdf_input[kdf_length];
    component j3a = Join3Arrays(79,48,length);
    j3a.array1 <== info;
    j3a.array2 <== t_hsenc;
    j3a.array3 <== intro_secret_hs_input;
    kdf_input <== j3a.out_array;

    // Generate keys in bits (LE)
    // We will precalculate the MAC, so we don't need to calculate the MAC key
    // The IV is all 0s, so we also don't need to calculate the IV
    component shake256 = SHAKE256_bytes(kdf_length, 32); // S_KEY_LEN = 32
    shake256.inp_bytes <== kdf_input;

    signal output key[256];
    component unpack = UnpackBytes(32);
    unpack.bytes <== shake256.out_bytes;
    key <== unpack.bits;

}