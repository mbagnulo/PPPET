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

print(2**7 + 2**6)