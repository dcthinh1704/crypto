
from Crypto.Util.number import *

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from sage.all import *
from tqdm import trange
import random
import os


def generate_key(E, P):
    private_key = randint(1, P.order() - 1)

    public_key = private_key * P

    key = public_key[0]

    key_int = int(key)

    key_bytes = key_int.to_bytes(16, 'big')

    return key_bytes

def encrypt_file(input_file, output_file, key):
    key_bytes = key

    with open(input_file, 'rb') as f:
        data = f.read()

    cipher = AES.new(key_bytes, AES.MODE_CBC)

    cipher_text = cipher.encrypt(pad(data, AES.block_size))

    with open(output_file, 'wb') as f:
        f.write(cipher_text)

if __name__ == "__main__":
    p = getPrime(32)
    a, b = random.randint(0, p-1), random.randint(0, p-1)
    E = EllipticCurve(GF(p), [a, b])
    P = E.random_point()

    key = generate_key(E, P)

    print("P =", P)
    n = randint(1, P.order() - 1)
    Q = n * P
    print("Q =", Q)
    print("E =", E)
    print("a = ", a)
    print("b =", b)
    print(n)
    
    input_file = 'input.pdf'
    
    output_file = 'encrypted.pdf'

    # encrypt_file(input_file, output_file, key)

    # print("File has been encrypted successfully.")
