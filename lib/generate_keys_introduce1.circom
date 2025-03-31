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

/* Use signals instead of variable for constants? Code could be simplified with Join2Arrays and Join3Arrays from utils, but we may
need more constraints to guarantee their value wasn't modified + bigger witness file? */

// Generates N_hs_cred = H("credential" | public-identity-key)
template GenerateNHsCred(){
    signal input kp_hs_id[32];
    signal output out[32];

    // "credential" in bytes (ASCII)
    var credential[10] = [99, 114, 101, 100, 101, 110, 116, 105, 97, 108];

    // Create preimage
    // Check that arrays are copied properly with a restriction
    signal preimage[42];
    component iseq[42];
    var j = 0;
    for(var i = 0; i < 10; i++){
        iseq[j] = ForceEqual();
        preimage[j] <== credential[i];
        iseq[j].in[0] <== credential[i];
        iseq[j].in[1] <== preimage[j];
        j++;
    }

    for(var i = 0; i < 32; i++){
        iseq[j] = ForceEqual();
        preimage[j] <== kp_hs_id[i];
        iseq[j].in[0] <== kp_hs_id[i];
        iseq[j].in[1] <== preimage[j];
        j++;
    }

    // Calculate n_hs_cred
    component sha3 = SHA3_256_bytes(42);
    sha3.inp_bytes <== preimage;
    out <== sha3.out_bytes;
}

// N_hs_subcred = H("subcredential" | N_hs_cred | blinded-public-key)
template GenerateNHsSubcred(){
    signal input blinded_key[32];
    signal input n_hs_cred[32];
    signal output out[32];

    // "subcredential" in bytes (ASCII)
    var subcredential[13] = [115, 117, 98, 99, 114, 101, 100, 101, 110, 116, 105, 97, 108];
    signal preimage[77];
    component iseq[77];

    var j = 0;
    for(var i = 0; i < 13; i++){
        iseq[j] = ForceEqual();
        preimage[j] <== subcredential[i];
        iseq[j].in[0] <== subcredential[i];
        iseq[j].in[1] <== preimage[j];
        j++;
    }

    for(var i = 0; i < 32; i++){
        iseq[j] = ForceEqual();
        preimage[j] <== n_hs_cred[i];
        iseq[j].in[0] <== n_hs_cred[i];
        iseq[j].in[1] <== preimage[j];
        j++;
    }

    for(var i = 0; i < 32; i++){
        iseq[j] = ForceEqual();
        preimage[j] <== blinded_key[i];
        iseq[j].in[0] <== blinded_key[i];
        iseq[j].in[1] <== preimage[j];
        j++;
    }

    // Calculate n_hs_subcred
    component sha3 = SHA3_256_bytes(77);
    sha3.inp_bytes <== preimage;
    out <== sha3.out_bytes;
}

// Generates the "info" parameter
// info = m_hsexpand | N_hs_subcred
template GenerateInfo(){
    signal input blinded_key[32];
    signal input kp_hs_id[32];

    signal output out[79];

    // "tor-hs-ntor-curve25519-sha3-256-1:hs_key_expand" in bytes (ASCII)
    var m_hsexpand[47] = [116, 111, 114, 45, 104, 115, 45, 110, 116, 111, 114, 45, 99, 117, 114, 118, 101, 50, 53, 53, 49, 57, 45, 115, 104, 97, 51, 45, 50, 53, 54, 45, 49, 58, 104, 115, 95, 107, 101, 121, 95, 101, 120, 112, 97, 110, 100];
    
    // Get n_hs_subcred
    component nhscred = GenerateNHsCred();
    component nhsubcred = GenerateNHsSubcred();
    nhscred.kp_hs_id <== kp_hs_id;
    nhsubcred.blinded_key <== blinded_key;
    nhsubcred.n_hs_cred <== nhscred.out;

    component iseq[79];
    var j = 0;
    for(var i = 0; i < 47; i++){
        iseq[j] = ForceEqual();
        out[j] <== m_hsexpand[i];
        iseq[j].in[0] <== m_hsexpand[i];
        iseq[j].in[1] <== out[j];
        j++;
    }

    for(var i = 0; i < 32; i++){
        iseq[j] = ForceEqual();
        out[j] <== nhsubcred.out[i];
        iseq[j].in[0] <== nhsubcred.out[i];
        iseq[j].in[1] <== out[j];
        j++;
    }
}

template GenerateKeyIntroduce1(){
    signal input kp_hs_id[32];
    signal input blinded_key[32];
    // intro_secret_hs_input = EXP(B,x) | AUTH_KEY | X | B | "tor-hs-ntor-curve25519-sha3-256-1"
    signal input intro_secret_hs_input[129]; // intro_secret_hs_input in bytes

    // "tor-hs-ntor-curve25519-sha3-256-1:hs_key_extract" in bytes (ASCII)
    var t_hsenc[48] = [116, 111, 114, 45, 104, 115, 45, 110, 116, 111, 114, 45, 99, 117, 114, 118, 101, 50, 53, 53, 49, 57, 45, 115, 104, 97, 51, 45, 50, 53, 54, 45, 49, 58, 104, 115, 95, 107, 101, 121, 95, 101, 120, 116, 114, 97, 99, 116];

    // Generate "info" parameter
    component info = GenerateInfo();
    info.blinded_key <== blinded_key;
    info.kp_hs_id <== kp_hs_id;

    // Generate input for keys = KDF(...)
    // hs_keys = KDF(intro_secret_hs_input | t_hsenc | info, S_KEY_LEN+MAC_LEN) | We don't calculate MAC here
    // ENC_KEY = hs_keys[0:S_KEY_LEN]
    var preimage_length = 256;  // 129 + 48 + 79

    signal preimage[preimage_length];
    component iseq[preimage_length];
    var j = 0;
    for(var i = 0; i < 129; i++){
        iseq[j] = ForceEqual();
        preimage[j] <== intro_secret_hs_input[i];
        iseq[j].in[0] <== intro_secret_hs_input[i];
        iseq[j].in[1] <== preimage[j];
        j++;
    }

    for(var i = 0; i < 48; i++){
        iseq[j] = ForceEqual();
        preimage[j] <== t_hsenc[i];
        iseq[j].in[0] <== t_hsenc[i];
        iseq[j].in[1] <== preimage[j];
        j++;
    }

    for(var i = 0; i < 79; i++){
        iseq[j] = ForceEqual();
        preimage[j] <== info.out[i];
        iseq[j].in[0] <== info.out[i];
        iseq[j].in[1] <== preimage[j];
        j++;
    }

    // Generate keys in bits
    component shake256 = SHAKE256_bytes(preimage_length, 32); // S_KEY_LEN = 32
    shake256.inp_bytes <== preimage;

    signal output key[256];
    component b2b = BytesToBits(32);
    b2b.in <== shake256.out_bytes;
    key <== b2b.out;
}