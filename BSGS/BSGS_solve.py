from sage.all import *
from tqdm import trange

def bsgs_ecdlp(P, Q, E):
    if Q == E((0, 1, 0)):
        return P.order()
    if Q == P:
        return 1
    m = ceil(sqrt(P.order()))
    lookup_table = {j*P: j for j in range(m)}
    for i in trange(m):  
        temp = Q - (i*m)*P
        if temp in lookup_table:
            return (i*m + lookup_table[temp]) % P.order()
    return None

if __name__ == "__main__":
    P_info = (3510480258, 2322356449)
    Q_info = (3565697714, 998548578)

    a_info = 2482207540
    b_info = 166359566
    field_info = "3720387343"

    E = EllipticCurve(GF(int(field_info)), [a_info, b_info])

    P = E(P_info)
    Q = E(Q_info)

    x = bsgs_ecdlp(P, Q, E)
    if x is not None:
        print("Private key found successfully:", x)
    else:
        print("Failed to find private key.")
