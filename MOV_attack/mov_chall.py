from sage.all import * 
import random 
from hashlib import sha1
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import json
import binascii

def pad(m):
    return m + chr(16 - len(m) % 16) * (16 - len(m) % 16)

def AES_CBC_Encrypt(flag, secret):
    # Set key & IV for AES CBC
    aes_key = secret.to_bytes(64, byteorder='little')[0:16]
    IV = bytes.fromhex('656e6372797074696f6e496e74566563')
    cipher = AES.new(aes_key, AES.MODE_CBC, IV)

    encrypt_flag = cipher.encrypt(pad(flag).encode('utf-8'))

    return binascii.hexlify(encrypt_flag)

def GenerateRandomCurve():
    # Curve params
    with open("super_singular_curves.json", 'r') as f:
        curves = json.loads(f.read())
    index = randint(0, len(curves) -1 ) # Get random index of curve in json file

    p = curves[index]['p']
    a = curves[index]['a']
    b = curves[index]['b']

    print("\n(+) The curve parameters are:")
    print(f"p = {p}")
    print(f"a = {a}")
    print(f"b = {b}")

    curve = EllipticCurve(GF(p), [a, b])

    assert curve.order() == p + 1 # curve is a supersingular curve when #E(f_p) == p + 1

    return curve

# Main def
if __name__ == "__main__":
    # Generate curve
    E = GenerateRandomCurve()

    P = E.gen(0)
    secret = random.randint(1, P.order() - 1)
    # Print information of 2 points P and Q where Q = secret * P
    print("\n(+) Points: ")
    print(f'{P = }')
    print(f'Q = {P * secret}')

    # open file to get plaintext
    with open("flag.txt", "r") as file:
        flag = file.read()

    # Encrypted flag with key=secret
    encrypted_flag = AES_CBC_Encrypt(flag, secret)

    print(f"\n(+) Encrypted Flag: {encrypted_flag}")

    # # Uncomment this line code to check secret with your exploited one
    # print(f"\n(+) Secret: {secret}")