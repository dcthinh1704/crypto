#!/usr/bin/python3 
from sage.all import * 
from Crypto.Cipher import AES
import hashlib
from tqdm import trange

p = 115792089210356248762697446949407573530086143415290314195533631308867097853951
a = 115792089210356248762697446949407573530086143415290314195533631308867097853948
b = 1235004111951061474045987936620314048836031279781573542995567934901240450608

E = EllipticCurve(GF(p), [a,b])

P = E(58739589111611962715835544993606157139975695246024583862682820878769866632269, 86857039837890738158800656283739100419083698574723918755107056633620633897772)
Q = E(53389524449399713241908666754198583135391726383277973572010353430393882869587, 96915749683251448875914358893119124077807308307116979366734609648027786948994)

with open('flag.enc', 'rb') as f:
    dataCipher = f.read()
    iv = dataCipher[:16]
    encrypted_flag = dataCipher[16:]

n = P.order()
fac = factor(n)
print(f"factors: {fac}")
d = []
subgroup = []

# Sử dụng tqdm để hiển thị tiến trình của vòng lặp
for i in trange(len(fac), desc='Calculating discrete logs'):
    prime, exponent = fac[i]
    P0 = (n // (prime ** exponent)) * P 
    Q0 = (n // (prime ** exponent)) * Q
    x = discrete_log(Q0, P0, operation='+')
    d.append(x)
    print(f"x = {x}  mod({prime**exponent})")
    subgroup.append(prime**exponent)

print("Calculating in CRT...")
secret = crt(d, subgroup)
print(f"=> x = {secret} mod ({n})")
assert secret * P == Q

sha1 = hashlib.sha1()
sha1.update(str(secret).encode('ascii'))
key = sha1.digest()[:16]
cipher = AES.new(key, AES.MODE_CBC, iv) 
recover = cipher.decrypt(encrypted_flag)

with open('recovered.txt', 'wb') as file:
    file.write(recover)
