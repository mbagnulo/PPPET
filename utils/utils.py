import hashlib
import random

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
# Used to reverse UnpackBytes() output in Circom
# Input is assumed to be in little endian
def bits_to_bytes_array(bit_sequence):
    if len(bit_sequence) % 8 != 0:
        raise ValueError("Length must be multiple of 8")
    
    # you can comment this next line if you want to use a big endian as input
    bit_sequence = bit_sequence[::-1]

    bytes_list = []
    for i in range(0, len(bit_sequence), 8):
        byte_str = bit_sequence[i:i+8]
        byte = int(byte_str, 2)
        bytes_list.append(byte)

    bytes_list.reverse()

    return bytes_list

# UnpackBytes() in Circom
def bytes_array_to_bits(l):
    bit_sequence = ""
    for num in l:
        b = to_bin(num, 8)
        b_le = b[::-1]
        bit_sequence += b_le

    return bit_sequence

def bit_string_to_array(b):
    bit_list = []
    for bit in b:
        bit_list.append(int(bit))

    return bit_list


# Turns hexadecimal sequence into array of bytes (0-255)
def hex_string_to_bytes(hex_string):
    if len(hex_string) % 2 != 0:
        raise ValueError("Wrong length")

    byte_array = []

    for i in range(0, len(hex_string), 2):
        byte = int(hex_string[i:i+2], 16)  # Convertir los caracteres hexadecimales a un entero
        byte_array.append(byte)  # Agregar el byte al array

    return byte_array

def bytes_to_hex(byte_array):
    return ''.join(f'{byte:02x}' for byte in byte_array)

def hex_to_bytes(hex_string):
    if len(hex_string) % 2 != 0:
        raise ValueError("Wrong length")
    
    byte_array = [int(hex_string[i:i+2], 16) for i in range(0, len(hex_string), 2)]
    
    return byte_array
