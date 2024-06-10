import math
from Crypto.Util.number import getPrime

# Số nguyên lớn
p = 115792089210356248762697446949407573530086143415290314195533631308867097853951

# Tính độ dài bit của p
bit_length = math.ceil(math.log2(p))
print(f"Bit length of p: {bit_length}")

# Sinh số nguyên tố có độ dài bit tương ứng
prime = getPrime(bit_length)
print(f"Generated prime: {prime}")