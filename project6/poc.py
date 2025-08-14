from hashlib import sha256
from typing import Tuple
import secrets


q = int("8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3", 16)
a = int("787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498", 16)
b = int("63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A", 16)
Gx = int("421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D", 16)
Gy = int("0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2", 16)
n = int("8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7", 16)
O = None  # Point at infinity


# Basic EC point operations

def inv_mod(x: int, p: int) -> int:
    return pow(x, p-2, p)

def is_on_curve(P):
    if P is None:
        return True
    x, y = P
    return (y * y - (x * x * x + a * x + b)) % q == 0

def point_add(P, Q):
    if P is None: return Q
    if Q is None: return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % q == 0:
        return None
    if P == Q:
        lam = (3 * x1 * x1 + a) * inv_mod(2 * y1, q) % q
    else:
        lam = (y2 - y1) * inv_mod(x2 - x1, q) % q
    x3 = (lam * lam - x1 - x2) % q
    y3 = (lam * (x1 - x3) - y1) % q
    return (x3, y3)

def scalar_mul(k: int, P):
    if k % n == 0 or P is None:
        return None
    if k < 0:
        return scalar_mul(-k, (P[0], (-P[1]) % q))
    R = None
    N = P
    while k:
        if k & 1:
            R = point_add(R, N)
        N = point_add(N, N)
        k >>= 1
    return R




def sm3(msg: bytes) -> bytes:
    # Using SHA-256 for SM3 (placeholder)
    return sha256(msg).digest()

def sm3_int(msg: bytes) -> int:
    return int.from_bytes(sm3(msg), 'big')


def sm2_keygen() -> Tuple[int, Tuple[int, int]]:
    d = secrets.randbelow(n - 1) + 1
    P = scalar_mul(d, (Gx, Gy))
    return d, P

def sm2_sign(d: int, IDA: bytes, M: bytes, k: int) -> Tuple[int, int]:
    e = sm3_int(M) % n
    kG = scalar_mul(k, (Gx, Gy))
    if kG is None:
        raise ValueError("kG = O")
    x1, y1 = kG
    r = (e + x1) % n
    if r == 0 or r + k == n:
        raise ValueError("bad r")
    s = (inv_mod(1 + d, n) * (k - r * d)) % n
    if s == 0:
        raise ValueError("bad s")
    return r, s

def sm2_verify(P: Tuple[int, int], IDA: bytes, M: bytes, signature: Tuple[int, int]) -> bool:
    r, s = signature
    if not (1 <= r <= n - 1 and 1 <= s <= n - 1):
        return False
    e = sm3_int(M) % n
    t = (r + s) % n
    if t == 0:
        return False
    x1y1 = point_add(scalar_mul(s, (Gx, Gy)), scalar_mul(t, P))
    if x1y1 is None:
        return False
    x1, y1 = x1y1
    R = (e + x1) % n
    return R == r

def recover_private_key(r1, s1, r2, s2, e1, e2) -> int:
    num = (s2 - s1) % n
    den = (s1 + r1 - s2 - r2) % n
    if den == 0:
        raise ValueError("Denominator is zero")
    return (num * inv_mod(den, n)) % n


if __name__ == "__main__":
    IDA = b"ALICE"
    M1 = b"Message 1"
    M2 = b"Message 2"


    d, P = sm2_keygen()
    print("Private key d:", hex(d))

 
    k = secrets.randbelow(n - 1) + 1
    print("Fixed k:", hex(k))


    sig1 = sm2_sign(d, IDA, M1, k)
    sig2 = sm2_sign(d, IDA, M2, k)
    print("Signature 1:", sig1)
    print("Signature 2:", sig2)


    assert sm2_verify(P, IDA, M1, sig1)
    assert sm2_verify(P, IDA, M2, sig2)


    r1, s1 = sig1
    r2, s2 = sig2
    e1 = sm3_int(M1) % n
    e2 = sm3_int(M2) % n
    recovered_d = recover_private_key(r1, s1, r2, s2, e1, e2)
    print("Recovered private key:", hex(recovered_d))

    print("Private key match:", d == recovered_d)
