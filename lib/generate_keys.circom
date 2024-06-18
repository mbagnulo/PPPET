pragma circom 2.0.0;

include "hash_circuits/keccak/sha3_bytes.circom";
include "utils.circom";

/*
Generates keys for encryption of descriptor plaintext

The subcredential for a period is derived as:

    N_hs_subcred = H("subcredential" | N_hs_cred | blinded-public-key).

In the above formula, credential corresponds to:

    N_hs_cred = H("credential" | public-identity-key)

   where public-identity-key is the public identity master key of the hidden
   service.

SALT = 16 bytes from H(random)
secret_input = SECRET_DATA | N_hs_subcred | INT_8(revision_counter)
	SECRET_DATA = blinded-public-key (we don't consider client authentication)
	STRING_CONSTANT = "hsdir-encrypted-data" | "hsdir-superencrypted-data" (depends of layer)

keys = KDF(secret_input | salt | STRING_CONSTANT, S_KEY_LEN + S_IV_LEN + MAC_KEY_LEN)
    SECRET_KEY = first S_KEY_LEN bytes of keys
    SECRET_IV  = next S_IV_LEN bytes of keys
    MAC_KEY    = last MAC_KEY_LEN bytes of keys

For the length values:
    S_KEY_LEN = 32 bytes, since we use AES256 for encryption
    S_IV_LEN = 16 bytes
    MAC_KEY_LEN = 0, we only need the key and IV for encryption of descriptors

Instantiate KDF with SHAKE-256
*/

// Calculates N_hs_subcred
template GenerateSubcredentials(){
    signal input kp_hs_id[32];
    signal input blinded_key[32];
    signal output n_hs_subcred[32];

    signal n_hs_cred[32];

    // "credential" and "subcredential" converted to bytes (LE) with ASCII
    signal credential[10] <== [108, 97, 105, 116, 110, 101, 100, 101, 114, 99];
    signal subcredential[13] <== [108, 97, 105, 116, 110, 101, 100, 101, 114, 99, 98, 117, 115];

    // Find N_hs_cred
    component j2a = Join2Arrays(32,10);
    j2a.array1 <== kp_hs_id;
    j2a.array2 <== credential;
    
    component sha3_1 = SHA3_256_bytes(42);
    sha3_1.inp_bytes <== j2a.out_array;
    n_hs_cred <== sha3_1.out_bytes;

    // Find N_hs_subcred
    component j3a = Join3Arrays(32, 32, 13);
    j3a.array1 <== blinded_key;
    j3a.array2 <== n_hs_cred;
    j3a.array3 <== subcredential;

    component sha3_2 = SHA3_256_bytes(77);
    sha3_2.inp_bytes <== j3a.out_array;
    n_hs_subcred <== sha3_2.out_bytes;
}

template GenerateKeys(){
    signal input kp_hs_id[32]; // kp_hs_id in bytes (LE)
    signal input blinded_key[32]; // Blinded key in bytes (LE)
    signal input salt[16]; // Salt in bytes (LE)

    // Generate N_hs_subcred
    signal n_hs_subcred[32];
    component subcred_gen = GenerateSubcredentials();
    subcred_gen.kp_hs_id <== kp_hs_id;
    subcred_gen.blinded_key <== blinded_key;
    n_hs_subcred <== subcred_gen.n_hs_subcred;



}
component main = GenerateKeys();