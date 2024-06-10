from sage.all import * 
from Crypto.Cipher import AES 
import binascii

# Decrypt cipher to get flag
def AES_CBC_Decrypt(encrypted, key):
    aes_key = key.to_bytes(64, byteorder='little')[0:16]
    IV = b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'
    cipher = AES.new(aes_key, AES.MODE_CBC, IV)

    flag = cipher.decrypt(binascii.unhexlify(encrypted))

    return flag

# Lifts a point to the p-adic field.
def _lift(E, P, gf):
    x, y = map(ZZ, P.xy())
    for point_ in E.lift_x(x, all=True):
        _, y_ = map(gf, point_.xy())
        if y == y_:
            return point_
        
def Smart_Attack(P, Q):
    """
    Solves the discrete logarithm problem using Smart's attack.
    More information: Smart N. P., "The discrete logarithm problem on elliptic curves of trace one"
    :param P: the base point
    :param Q: the point multiplication result
    :return: secret such that secret * P == Q
    """
    E = P.curve()
    gf = E.base_ring()
    p = gf.order()
    assert E.trace_of_frobenius() == 1, f"Curve should have trace of Frobenius = 1."

    E = EllipticCurve(Qp(p), [int(a) + p * ZZ.random_element(1, p) for a in E.a_invariants()])

    P = p * _lift(E, P, gf)
    Q = p * _lift(E, Q, gf)

    x_P, y_P = P.xy()
    x_Q, y_Q = Q.xy()

    psi_P = -(x_P / y_P)
    psi_Q = -(x_Q / y_Q)

    k = gf(psi_Q / psi_P)

    return int(k)

# Main def
if __name__ == "__main__":
    # Inforamtion of curve
    p = 89839996137262766214523008916288277520454963509062772873376712482635122182481
    a = 21782015965216748259055159348930797314268996884578908521123301121799191461186
    b = 19060248880287277540197027792912251232060326776480855951005948793571254123638
    E = EllipticCurve(GF(p), [a,b])

    # information of 2 points of upper curve
    P = E(41674234679242321157156170702951991130915358329187392911943872359039698457575,
        49978105001678172551035598996565370236973616619685829074258519155789909743020)

    Q = E(30289655768462464048526399010336976867285246789222909571024536303012736453062, 
        29546546540823793600014060278694839066048519561778054903733139977471063000729)
    
    encrypted_flag = b'e137a31bc812872f4c2631b9891dcb01fcc8289918abd037055797df1d9e12c1979d398ec7d6c68f3291e327c6a71e0c'

    # Attack the curve with Smart Attack method to get the secret
    secret = Smart_Attack(P, Q)

    # check if secret is correct, throw errow if not correct
    assert P * secret == Q
    print(f"\n(+) Secret found: {secret}")

    # Decrypt flag
    decrypted_flag = AES_CBC_Decrypt(encrypted_flag, secret)
    print(f"\n(+) Decrypted flag: {decrypted_flag}\n")