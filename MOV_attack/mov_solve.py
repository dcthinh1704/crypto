from math import gcd
from sage.all import *
from Crypto.Cipher import AES 
import binascii

# Decrypt cipher to get flag
def AES_CBC_Decrypt(encrypted, key):
    aes_key = key.to_bytes(64, byteorder='little')[0:16]
    IV = bytes.fromhex('656e6372797074696f6e496e74566563')
    cipher = AES.new(aes_key, AES.MODE_CBC, IV)

    flag = cipher.decrypt(binascii.unhexlify(encrypted))

    return flag

def MOV_Attack(E, P1, P2):
	order = E.order() # order of curve
	n = P1.order() # order of point P1

	print(f'\n=== Calculating embedding degree... ===')
	k = 1
	while (p ** k - 1) % order:
		k += 1
	print(f'(+) Found embedding degree: {k}')

	# Extends the base field from GF(p) to GF(p ^ k)
	EK = E.base_extend(GF(p ** k))
	PK = EK(P2)
	GK = EK(P1)

	# find a point Q on extended elliptic curve EK which:
	while True:
		R = EK.random_point()
		m = R.order()
		d = gcd(m,n)
		Q = (m // d) * R
		if n / Q.order() not in ZZ:
			continue
		if n == Q.order():
			break

	# Calculate pairing with weil_pairing
	print(f'\n=== Computing pairings for alpha, beta... ===')
	alpha = GK.weil_pairing(Q, n)
	beta = PK.weil_pairing(Q, n)
	print(f'(+) alpha: {alpha}')
	print(f'(+) beta: {beta}')

	# Calculate log to find secret
	print(f"\n=== Computing the log: \"beta.log(alpha)\" to find secret ... ===")
	return beta.log(alpha)
	

if __name__ == "__main__":
	# Curve parameters
	p = 899400035654513474896152347474441353171234147 
	a, b = 899400035654513474896152347474441353171234146, 0

	# Define curve
	E = EllipticCurve(GF(p), [a, b])

	# Point informations
	P1 = E(654091782186930182482649505926738454958454666 , 376137493156152746565800671049360734666492234)
	P2 = E(343006103311194154573650500820107946735703357 , 416967131357776050595965944158988018189770568)

	# Encrypted flag
	enc = b'f879eb3658c0379e2f050fee718d1a8ad0fdf41203cd011c6ea6e1c27f221707bc97fc419e83ffe8c1ca09d2de5f7cbf29740f1a24b233da9628ca46e92b836c'

	# Attack to find secret with MOV method
	secret = MOV_Attack(E, P1, P2)
	print(f"(+) Found secret: {secret}")

	# Decrypt to get flag
	print(f"\n=== Decrypting flag... ===")
	flag = AES_CBC_Decrypt(enc, int(secret))
	print(f"(+) Decrypted flag: {flag}")