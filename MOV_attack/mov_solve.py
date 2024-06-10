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
	alpha = GK.weil_pairing(Q,n)
	beta = PK.weil_pairing(Q,n)
	print(f'(+) alpha: {alpha}')
	print(f'(+) beta: {beta}')

	# Calculate log to find secret
	print(f"\n=== Computing the log: \"beta.log(alpha)\" to find secret ... ===")
	return beta.log(alpha)
	

if __name__ == "__main__":
	# Curve parameters
	p = 1643092227478429542113848289763860548786034923 
	a, b = 1643092227478429542113848289763860548786034922, 0

	# Define curve
	E = EllipticCurve(GF(p), [a, b])

	# Point informations
	P1 = E(794298163356864406199377878100983323932895067 , 482749801410886934498543767822646767858090021)
	P2 = E(114250950523779305193547344329809749786265907 , 1292753302721847594154808829070103502297416726)

	# Encrypted flag
	enc = b'8865bd5b3189956050ac30929b58b802a57f198a25323fd2a29bfe5acb4d685c2ec925e8606d6dec606e09064384bf5cfed07c4e9488761ac396a3fbf9d210fc'

	# Attack to find secret with MOV method
	secret = MOV_Attack(E, P1, P2)
	print(f"(+) Found secret: {secret}")

	# Decrypt to get flag
	print(f"\n=== Decrypting flag... ===")
	flag = AES_CBC_Decrypt(enc, int(secret))
	print(f"(+) Decrypted flag: {flag}")