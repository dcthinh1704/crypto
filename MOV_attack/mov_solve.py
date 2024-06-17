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
	"""
	Solves the discrete logarithm problem using the MOV attack.
	More information: Harasawa R. et al., "Comparing the MOV and FR Reductions in Elliptic Curve Cryptography" (Section 2)
	:param E: curve
	:param P: the base point
	:param R: the point multiplication result
	:return: secret such that secret * P == R
	"""
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
	#   1. n / Q.order() => integer
	#   2. n == Q.order()
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
	p = 360481269686447805508492771017449225722776643 
	a, b = 360481269686447805508492771017449225722776642, 0

	# Define curve
	E = EllipticCurve(GF(p), [a, b])

	# Point informations
	P1 = E(61026825449738433761663639920918850774100595 , 350847238598402202529546625353086265958183442)
	P2 = E(230803928877731128195798317990821579463258039 , 287900469252208536285001176072346064362316265)

	# Encrypted flag
	enc = b'786e9da35d2d6c5a15f9cd11e4a123eab227b9dc6c8b87f62ef03ea421dff688fd0b1ca493609e63ab292652d2670df75a24688c0dae322ac458edd5d9df8845'

	# Attack to find secret with MOV method
	secret = MOV_Attack(E, P1, P2)
	print(f"(+) Found secret: {secret}")

	# Decrypt to get flag
	print(f"\n=== Decrypting flag... ===")
	flag = AES_CBC_Decrypt(enc, int(secret))
	print(f"(+) Decrypted flag: {flag}")