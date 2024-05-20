"""
Takes a point in the curve (Kp_hs_id) represented as an array of 32 bytes and transforms it into the necessary
format by the Ed25519 Circom implementation (P[4][3]) (https://github.com/Electron-Labs/ed25519-circom/)

Points are represented as tuples (X, Y, Z, T) of extended coordinates, with x = X/Z, y = Y/Z, x*y = T/Z. Every array represents
a coordinate represented in base 2^85 (3 numbers [0, 2^85) concatenated to make the whole byte sequence).

Z is always 1, so (X, Y, Z, Y) -> (x, y, 1, x*y)

Code might fail if not enough memory (large integers turning into float due to lack of memory)

NOTE: When introducing the input in Circom, numbers must be represented as strings. Big ints lose precision if represented as numbers
when being entered as inputs in Circom.
"""

# Ed25519 implementation from https://datatracker.ietf.org/doc/html/rfc8032#section-6

# Base field Z_p
p = 2**255 - 19

def modp_inv(x):
    return pow(x, p-2, p)

# Curve constant
d = -121665 * modp_inv(121666) % p

# Group order
q = 2**252 + 27742317777372353535851937790883648493

# Square root of -1
modp_sqrt_m1 = pow(2, (p-1) // 4, p)

# Compute corresponding x-coordinate, with low bit corresponding to
# sign, or return None on failure
def recover_x(y, sign):
    if y >= p:
        return None
    x2 = (y*y-1) * modp_inv(d*y*y+1)
    if x2 == 0:
        if sign:
            return None
        else:
            return 0

    # Compute square root of x2
    x = pow(x2, (p+3) // 8, p)
    if (x*x - x2) % p != 0:
        x = x * modp_sqrt_m1 % p
    if (x*x - x2) % p != 0:
        return None

    if (x & 1) != sign:
        x = p - x
    return x

def point_decompress(s):
    if len(s) != 32:
        raise Exception("Invalid input length for decompression")
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1

    x = recover_x(y, sign)
    if x is None:
        return None
    else:
        return (x, y, 1, x*y % p)


# Base point
g_y = 4 * modp_inv(5) % p
g_x = recover_x(g_y, 0)
G = (g_x, g_y, 1, g_x * g_y % p)

###########################################

# Tranforms coordinate into 255 bits
def to_bin(n):
    # Just in case
    # n = n % p
    n_bin = bin(n)[2:]
    n_bin = n_bin.zfill(255)

    return n_bin

# Transforms 255 bit sequence into base2^85 representation
def to_base_2_85(n):
    n_1 = n[:85]
    n_2 = n[85:170]
    n_3 = n[170:]

    n_1 = int(n_1, 2)
    n_2 = int(n_2, 2)
    n_3 = int(n_3, 2)
    
    # Change order when storing it
    return [n_3, n_2, n_1]


# Transforms P(x, y, 1, x*y) into P[4][3] in base 2^85
def point_to_ed25519_circom(key):
    
    x = key[0]
    y = key[1]
    z = key[2]
    t = key[3]

    x_bin = to_bin(x)
    y_bin = to_bin(y)
    z_bin = to_bin(z)
    t_bin = to_bin(t)

    # Transforms to base 2^85
    x_base = to_base_2_85(x_bin)
    y_base = to_base_2_85(y_bin)
    z_base = to_base_2_85(z_bin)
    t_base = to_base_2_85(t_bin)

    return [x_base, y_base, z_base, t_base]


if __name__ == "__main__":

    # Point represented as a byte sequence, in our case it would be kp_hs_id
    # Example point
    kp_hs_id = [200,0, 1, 3, 5, 1, 12, 14, 5, 6, 99, 34, 9, 123, 4, 1, 1, 4, 4, 2, 1, 4, 1, 213, 2, 0, 0, 0, 1, 0, 1, 33]

    # Obtains (X, Y, Z, T)
    decoded_point = point_decompress(kp_hs_id)

    # Obtains P[4][3] in base 2^85
    point = point_to_ed25519_circom(decoded_point)
    print(point)
    print("NOTE: Remember to introduce the numbers as strings in Circom input.json")
