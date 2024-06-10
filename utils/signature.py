from point_to_base_2_85 import point_to_ed25519_circom, point_decompress
from utils import hex_to_bytes, bytes_array_to_bits, bit_string_to_array, to_bin, bits_to_bytes_array,bytes_to_hex

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

    # Transform merkle tree root into hexadecimal, use this to generate the signature
    # (for example https://cyphr.me/ed25519_tool/ed.html)
    root = 17627180145485382211428732651229903626705455119230262703278238456903644772624
    root_hex = bytes_to_hex(bits_to_bytes_array(to_bin(root, 256)[::-1]))

    # We convert the root to a 256 bits/64 hex sequence before signing it
    # We do this to avoid cases where the Poseidon hash outputs a small int (possible?) to
    # have a consistent size in the circuit when transforming the root to bits

    # The prime number used by Circom is lower than 2**254, so there cant be roots
    # with more than 256 bits

    print("Root in hexadecimal:")
    print(root_hex)

    # Find inputs for Circom
    #msg_hex = "af82"
    public_key_hex = "2F0022A99D9FD997146E31628C6539D4D9E6173A7A5C94D72B64F3C2AD8206F1"
    signature_hex = "8E159EE3C2C355BFECFBDDE7B52B9705EF9CFB5AF4ADCF4747820E339680E617D1626B5672664262B74E6C0EBBE83FD3B2F39083EF15D48EF61B5DB9DDA47B0F"

    r_hex = signature_hex[:64]
    s_hex = signature_hex[64:]

    #msg_bytes = hex_to_bytes(msg_hex)
    pk_bytes = hex_to_bytes(public_key_hex)
    r_bytes = hex_to_bytes(r_hex)
    s_bytes = hex_to_bytes(s_hex)

    #msg = bit_string_to_array(bytes_array_to_bits(msg_bytes))
    pk = bit_string_to_array(bytes_array_to_bits(pk_bytes))
    r = bit_string_to_array(bytes_array_to_bits(r_bytes))
    s = bit_string_to_array(bytes_array_to_bits(s_bytes))[:255]

    decoded_pk = point_decompress(pk_bytes)
    decoded_r = point_decompress(r_bytes)

    point_a = point_to_ed25519_circom(decoded_pk)
    point_r = point_to_ed25519_circom(decoded_r)

    print("INPUTS:")
    print("--------------")
    #print("msg:")
    #print(msg)
    print("")
    print("Root:")
    print(root)
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

    print("NOTE: Remember to introduce the large numbers as strings in Circom input.json")


