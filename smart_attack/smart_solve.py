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
    E = P.curve()
    gf = E.base_ring()
    p = gf.order()

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
    p = 59784930151316719996364554235716770019134611948098287615591143428518274574251
    a = 46661405073288521352779487744816765848445647923078609362054998907485126842337
    b = 42146267722598022150150994969828125286570369398303493292814407577455127828864
    E = EllipticCurve(GF(p), [a,b])

    # information of 2 points of upper curve
    P = E(34370081667922322073791202502663145532542737299905151136369295383566703347709,
        2349781797003227827747998392973379566493744349185354633873420758180833589282)

    Q = E(54658415211574498055894679822389741751698439517461232791264414770967051000679, 
        33767049771906477948794248191422224633660109990682933916403026539872143596979)

    encrypted_flag = b'46d3bb24e9a1da072be552c232bc6b433059fbb1a7feed8e60494902611874083c15190f840a46140eef5a39eadf1c13'

    # Attack the curve with Smart Attack method to get the secret
    secret = Smart_Attack(P, Q)

    # check if secret is correct, throw errow if not correct
    assert P * secret == Q
    print(f"\n(+) Secret found: {secret}")

    # Decrypt flag
    decrypted_flag = AES_CBC_Decrypt(encrypted_flag, secret)
    print(f"\n(+) Decrypted flag: {decrypted_flag}\n")