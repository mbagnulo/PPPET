pragma circom 2.0.0;

include "utils.circom";
include "base64/base64.circom";

// Compares "encrypted"/"superencrypted" base 64 field with encryption output
// length: byte length of encrypted plaintext
template CompareDescriptor(length){
    var b64_length = 4 * ((length + 2) \ 3);
    var bits_length = length * 8;
    signal input b64_field[b64_length]; // Base 64 field in BE bytes
    signal input enc_result[bits_length]; // Encryption output in LE bits

    // Decode Base64 field
    signal field_bytes[length];
    component decode = Base64Decode(length);
    decode.in <== b64_field;
    field_bytes <== decode.out;

    // Transform to LE bits
    signal field_bits[bits_length];
    component unpack = UnpackBytes_BE_to_LE(length);
    unpack.bytes <== field_bytes;
    field_bits <== unpack.bits;

    // Compare both arrays
    component eq_array = IsEqualArrays(bits_length);
    eq_array.array1 <== field_bits;
    eq_array.array2 <== enc_result;
}