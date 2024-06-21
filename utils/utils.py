import hashlib
import random
import base64

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

# PackBytes() in Circom (reverses UnpackBytes())
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
# int.from_bytes(l, "little") but the output is expressed as a sequence of bits in LE
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

def bytes_to_hex(byte_array):
    return ''.join(f'{byte:02x}' for byte in byte_array)

def hex_to_bytes(hex_string):
    if len(hex_string) % 2 != 0:
        raise ValueError("Wrong length")
    
    byte_array = [int(hex_string[i:i+2], 16) for i in range(0, len(hex_string), 2)]
    
    return byte_array

# Transforms a bytes array (BE) into Base64
def bytes_to_base64(byte_array):
    byte_data = bytes(byte_array)
    base64_encoded = base64.b64encode(byte_data)
    base64_string = base64_encoded.decode('ascii')
    
    return base64_string

# Transforms text into a bytes array (BE) using ASCII
def text_to_byte_array(text):
    byte_data = text.encode('ascii')
    byte_array = list(byte_data)
    
    return byte_array

# Transforms text_file (for example, descriptors) into a bytes array (BE) using ASCII
def text_file_to_byte_array(file_path):
    with open(file_path, 'r', encoding='ascii') as file:
        text = file.read()
    byte_data = text.encode('ascii')
    byte_array = list(byte_data)
    return byte_array