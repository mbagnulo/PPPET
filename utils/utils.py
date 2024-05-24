import hashlib

# big endian to little endian or viceversa
def to_endian(b):
    return b[::-1]

def bin_to_int(b):
    return int(b, 2)

# Tranforms num into n bits
def to_bin(num, n):
    n_bin = bin(num)[2:]
    n_bin = n_bin.zfill(n)

    return n_bin

# Transforms a bit sequence into an array of bytes.
# Can be used to obtain the Circom inputs in the appropiate format
# Input must be in little endian (99% sure)
# Used to reverse UnpackBytes() output in Circom
def bits_to_bytes_array(bit_sequence):
    if len(bit_sequence) % 8 != 0:
        raise ValueError("Length must be multiple of 8")
    bit_sequence = bit_sequence[::-1]
    bytes_list = []
    for i in range(0, len(bit_sequence), 8):
        byte_str = bit_sequence[i:i+8]
        byte = int(byte_str, 2)
        bytes_list.append(byte)

    bytes_list.reverse()

    return bytes_list
