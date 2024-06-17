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
    p = 90508526792107266779231685184523848515863441507325525269957048574909078910097
    a = 71335296225558199681259997862706219528113526602228150982214697666689147850256
    b = 75727205146098541812916114329050773714208127819808147060145796071749946320482
    E = EllipticCurve(GF(p), [a,b])

    # information of 2 points of upper curve
    P = E(60506352099779484925468563945475965366654596006469683564899413042655675901051,
        66210420151727964449747119557377955868271883071839661020870137844993247719519)

    Q = E(30241547740411531453219194660240841536257340342452979762297550236282677893108, 
        28075280343144775775991302701630226096369532196641097083470885357854515667105)

    encrypted_flag = b'618afc49e1d9b13083add1f9a84b0385305e86f47a289a395ebc75c30d0f53fda48e4956e5e1af5915cff2102ce2cbac'

    # Attack the curve with Smart Attack method to get the secret
    secret = Smart_Attack(P, Q)

    # check if secret is correct, throw errow if not correct
    assert P * secret == Q
    print(f"\n(+) Secret found: {secret}")

    # Decrypt flag
    decrypted_flag = AES_CBC_Decrypt(encrypted_flag, secret)
    print(f"\n(+) Decrypted flag: {decrypted_flag}\n")