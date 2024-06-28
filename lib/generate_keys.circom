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

// Calculates secret_input
template GenerateSecretInput(){
    signal input kp_hs_id[32];
    signal input blinded_key[32];
    signal input rev_counter[8];
    signal output secret_input[72];

    signal n_hs_cred[32];
    signal n_hs_subcred[32];

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

    // Find secret_input
    component j3a_2 = Join3Arrays(8, 32, 32);
    j3a_2.array1 <== rev_counter;
    j3a_2.array2 <== n_hs_subcred;
    j3a_2.array3 <== blinded_key;

    secret_input <== j3a_2.out_array;

}

// Generate keys needed to encrypt inner layer plaintext and obtain the "encrypted" field of the outer layer
template GenerateKeys_InnerLayer(){
    signal input kp_hs_id[32]; // kp_hs_id in bytes (LE)
    signal input blinded_key[32]; // Blinded key in bytes (LE)
    signal input salt[16]; // Salt in bytes (LE)
    signal input rev_counter[8]; // Descriptor revision counter in bytes (LE)

    signal output secret_key_bits[256];
    signal output secret_iv_bits[128];

    signal secret_key[32];
    signal secret_iv[16];

    // Generate secret_input (LE)
    signal secret_input[72];
    component input_gen = GenerateSecretInput();
    input_gen.kp_hs_id <== kp_hs_id;
    input_gen.blinded_key <== blinded_key;
    input_gen.rev_counter <== rev_counter;
    secret_input <== input_gen.secret_input;

    // "hsdir-encrypted-data" in LE
    signal STRING_CONSTANT[20] <== [97, 116, 97, 100, 45, 100, 101, 116, 112, 121, 114, 99, 110, 101, 45, 114, 105, 100, 115, 104];

    // Generate input for keys = KDF(...) (LE)
    signal kdf_input[108];
    component j3a = Join3Arrays(20,16,72);
    j3a.array1 <== STRING_CONSTANT;
    j3a.array2 <== salt;
    j3a.array3 <== secret_input;
    kdf_input <== j3a.out_array;

    // We don't add descriptor cookie to the blinded public key since we don't consider client authorization

    // Generate keys (LE)
    signal keys[48];
    component shake256 = SHAKE256_bytes(108, 48); // 48 = 32 (S_KEY_LEN) + 16 (S_IV_LEN) + 0 (MAC_KEY_LEN)
    shake256.inp_bytes <== kdf_input;
    keys <== shake256.out_bytes;

    component s2a = Separate2Arrays(16,32);
    s2a.in_array <== keys;
    secret_iv <== s2a.out_array1;
    secret_key <== s2a.out_array2;

    // Pass key and IV to bits
    component unpack1 = UnpackBytes(16);
    unpack1.bytes <== secret_iv;
    secret_iv_bits <== unpack1.bits;
    component unpack2 = UnpackBytes(32);
    unpack2.bytes <== secret_key;
    secret_key_bits <== unpack2.bits;

}

// Generate keys needed to encrypt outer layer plaintext and obtain the "superencrypted" field of the descriptor header
template GenerateKeys_OuterLayer(){
    signal input kp_hs_id[32]; // kp_hs_id in bytes (LE)
    signal input blinded_key[32]; // Blinded key in bytes (LE)
    signal input salt[16]; // Salt in bytes (LE)
    signal input rev_counter[8]; // Descriptor revision counter in bytes (LE)

    signal output secret_iv_bits[128];
    signal output secret_key_bits[256];

    signal secret_key[32];
    signal secret_iv[16];

    // Generate secret_input (LE)
    signal secret_input[72];
    component input_gen = GenerateSecretInput();
    input_gen.kp_hs_id <== kp_hs_id;
    input_gen.blinded_key <== blinded_key;
    input_gen.rev_counter <== rev_counter;
    secret_input <== input_gen.secret_input;

    // "hsdir-superencrypted-data" in LE
    signal STRING_CONSTANT[25] <== [97, 116, 97, 100, 45, 100, 101, 116, 112, 121, 114, 99, 110, 101, 114, 101, 112, 117, 115, 45, 114, 105, 100, 115, 104];

    // Generate input for keys = KDF(...) (LE)
    signal kdf_input[113];
    component j3a = Join3Arrays(25,16,72);
    j3a.array1 <== STRING_CONSTANT;
    j3a.array2 <== salt;
    j3a.array3 <== secret_input;
    kdf_input <== j3a.out_array;

    // Generate keys (LE)
    signal keys[48];
    component shake256 = SHAKE256_bytes(113, 48); // 48 = 32 (S_KEY_LEN) + 16 (S_IV_LEN) + 0 (MAC_KEY_LEN)
    shake256.inp_bytes <== kdf_input;
    keys <== shake256.out_bytes;

    component s2a = Separate2Arrays(16,32);
    s2a.in_array <== keys;
    secret_iv <== s2a.out_array1;
    secret_key <== s2a.out_array2;

    // Pass key and IV to bits
    component unpack1 = UnpackBytes(16);
    unpack1.bytes <== secret_iv;
    secret_iv_bits <== unpack1.bits;
    component unpack2 = UnpackBytes(32);
    unpack2.bytes <== secret_key;
    secret_key_bits <== unpack2.bits;
}

//component main = GenerateKeys_InnerLayer();
//component main = GenerateKeys_OuterLayer();

