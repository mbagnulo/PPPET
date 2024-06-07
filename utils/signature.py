from point_to_base_2_85 import point_to_ed25519_circom, point_decompress
from utils import hex_to_bytes, bytes_array_to_bits, bit_string_to_array

"""
Used to obtain the inputs for ip.circom (Circom implementation of IP policy)
    msg is the data for the signature

    R8 is the first 256 bits of the signature (LSB to MSB)

    S is the first 255 bits of the last 256 bits of the signature (LSB to MSB)

    A is the public key in binary (LSB to MSB)

    PointA is the point representing the public key on the elliptic curve (encoded in base 2^85 for brevity)

    PointR is the point representing the R8 value on the elliptic curve (encoded in base 2^85)
"""

if __name__ == "__main__":
    # Test inputs, change accordingly
    msg_hex = "af82"
    public_key_hex = "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"
    signature_hex = "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"

    r_hex = signature_hex[:64]
    s_hex = signature_hex[64:]

    msg_bytes = hex_to_bytes(msg_hex)
    pk_bytes = hex_to_bytes(public_key_hex)
    r_bytes = hex_to_bytes(r_hex)
    s_bytes = hex_to_bytes(s_hex)

    msg = bit_string_to_array(bytes_array_to_bits(msg_bytes))
    pk = bit_string_to_array(bytes_array_to_bits(pk_bytes))
    r = bit_string_to_array(bytes_array_to_bits(r_bytes))
    s = bit_string_to_array(bytes_array_to_bits(s_bytes))[:255]

    decoded_pk = point_decompress(pk_bytes)
    decoded_r = point_decompress(r_bytes)

    point_a = point_to_ed25519_circom(decoded_pk)
    point_r = point_to_ed25519_circom(decoded_r)

    print("msg:")
    print(msg)
    print("")

    print("A:")
    print(pk)
    print("")

    print("R8:")
    print(r)
    print("")

    print("S:")
    print(s)
    print("")

    print("PointA:")
    print(point_a)
    print("")

    print("PointR:")
    print(point_r)
    print("")

    print("NOTE: Remember to introduce the PointA and PointR numbers as strings in Circom input.json")


