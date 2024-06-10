

# This file was *autogenerated* from the file pollard_rho_chall.sage
from sage.all_cmdline import *   # import sage library

_sage_const_1 = Integer(1); _sage_const_25 = Integer(25); _sage_const_16 = Integer(16); _sage_const_0 = Integer(0); _sage_const_4 = Integer(4); _sage_const_3 = Integer(3); _sage_const_27 = Integer(27); _sage_const_2 = Integer(2)
from sage.all import *
from Crypto.Util.number import *
import random
import secrets
from Crypto.Cipher import AES 
from Crypto.Util.Padding import pad
from hashlib import sha3_512 # most secure hash I've heard :v

import os

def check(prime):
    if not isPrime(prime):
        print("Not a prime!!!")
        return False
    if prime <= (_sage_const_1 <<_sage_const_25 ):
        print("Your prime is so weak!!!")
        return False
    return True

def encrypt(key, mess):
    key = sha3_512(str(key).encode()).digest()[:_sage_const_16 ]
    iv = secrets.token_bytes(_sage_const_16 )
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(mess, AES.block_size))
    return iv + ct

def genPara(p):
    while True:
        a,b = random.randrange(_sage_const_0 ,p-_sage_const_1 ), random.randrange(_sage_const_0 ,p-_sage_const_1 )
        E = EllipticCurve(GF(p), [a,b])
        # make sure it's not a singular curve
        if (_sage_const_4 *a**_sage_const_3  + _sage_const_27  * b**_sage_const_2 ) % p != _sage_const_0  and isPrime(int(E.order())):
            return a,b


while True:
    p = int(input("Enter your prime: "))
    if check(p):
        break
secret = random.randint(_sage_const_0 ,p-_sage_const_1 )

F = GF(p)
a,b = genPara(p)
E = EllipticCurve(F, [a,b])
P = E.gens()[_sage_const_0 ] 
Q = P * secret

print(f'{a = }')
print(f'{b = }')
print(f'{p = }')
print('P =', P.xy())
print('Q =', Q.xy())


input_file_path = 'input.pdf'
#output_dir_path = '/output'


with open(input_file_path, 'rb') as file:
    pt = file.read()

#os.makedirs(output_dir_path, exist_ok=True)

ciphertext = encrypt(secret, pt)
with open("cipher.enc", "wb") as file:
    file.write(ciphertext)
    print("Write ciphertext to cipher.enc successfully!!!")

