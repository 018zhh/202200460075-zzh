
from __future__ import annotations
import struct, math, secrets, hmac
from typing import Tuple, Optional, Callable


q  = int("8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3", 16)
a  = int("787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498", 16)
b  = int("63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A", 16)
Gx = int("421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D", 16)
Gy = int("0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2", 16)
n  = int("8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7", 16)
O = None  # point at infinity representation


def inv_mod(x: int, p: int) -> int:
    return pow(x % p, p-2, p)

def is_on_curve(P: Optional[Tuple[int,int]]) -> bool:
    if P is None: return True
    x,y = P
    return (y*y - (x*x*x + a*x + b)) % q == 0

def point_add(P, Q):
    if P is None: return Q
    if Q is None: return P
    x1,y1 = P; x2,y2 = Q
    if x1 == x2:
        if (y1 + y2) % q == 0:
            return None
        # P == Q
        lam = (3 * x1 * x1 + a) * inv_mod(2 * y1, q) % q
    else:
        lam = (y2 - y1) * inv_mod(x2 - x1, q) % q
    x3 = (lam*lam - x1 - x2) % q
    y3 = (lam*(x1 - x3) - y1) % q
    return (x3, y3)

def scalar_mul(k: int, P):
    if P is None or k % n == 0:
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


IV = [
    0x7380166F,0x4914B2B9,0x172442D7,0xDA8A0600,
    0xA96F30BC,0x163138AA,0xE38DEE4D,0xB0FB0E4E
]

T_j = [0x79cc4519]*16 + [0x7a879d8a]*48

def _rotl(x, n):
    return ((x << n) & 0xFFFFFFFF) | (x >> (32-n))

def _P0(x): return x ^ _rotl(x,9) ^ _rotl(x,17)
def _P1(x): return x ^ _rotl(x,15) ^ _rotl(x,23)

def sm3_compress(V, B):
    W = []
    for i in range(16):
        W.append(int.from_bytes(B[4*i:4*i+4], 'big'))
    for j in range(16,68):
        x = W[j-16] ^ W[j-9] ^ _rotl(W[j-3],15)
        W.append(_P1(x) ^ _rotl(W[j-13],7) ^ W[j-6])
    W_ = [W[j] ^ W[j+4] for j in range(64)]

    A,Bb,C,D,E,F,G,H = V
    for j in range(64):
        SS1 = _rotl((_rotl(A,12) + E + _rotl(T_j[j], j % 32)) & 0xFFFFFFFF, 7)
        SS2 = SS1 ^ _rotl(A,12)
        if j <= 15:
            FF = A ^ Bb ^ C
            GG = E ^ F ^ G
        else:
            FF = (A & Bb) | (A & C) | (Bb & C)
            GG = (E & F) | ((~E) & G)
        TT1 = (FF + D + SS2 + W_[j]) & 0xFFFFFFFF
        TT2 = (GG + H + SS1 + W[j]) & 0xFFFFFFFF
        D = C
        C = _rotl(Bb,9)
        Bb = A
        A = TT1
        H = G
        G = _rotl(F,19)
        F = E
        E = _P0(TT2)
    return [(V[i] ^ x) & 0xFFFFFFFF for i,x in enumerate([A,Bb,C,D,E,F,G,H])]

def sm3_hash(msg: bytes) -> bytes:
    msg = bytearray(msg)
    l = len(msg) * 8
    msg.append(0x80)
    while ((len(msg)*8) % 512) != 448:
        msg.append(0x00)
    msg += l.to_bytes(8,'big')
    V = IV[:]
    for i in range(0, len(msg), 64):
        B = bytes(msg[i:i+64])
        V = sm3_compress(V, B)
    out = b''.join(v.to_bytes(4,'big') for v in V)
    return out


def sm3_int(msg: bytes) -> int:
    return int.from_bytes(sm3_hash(msg), 'big')


def hmac_sm3(key: bytes, data: bytes) -> bytes:
    block_size = 64
    if len(key) > block_size:
        key = sm3_hash(key)
    key = key.ljust(block_size, b'\x00')
    o_key = bytes((k ^ 0x5c) for k in key)
    i_key = bytes((k ^ 0x36) for k in key)
    return sm3_hash(o_key + sm3_hash(i_key + data))

def kdf(z: bytes, klen: int) -> bytes:
    # klen in bytes
    ct = 1
    res = b''
    for i in range(math.ceil(klen / 32)):
        res += sm3_hash(z + ct.to_bytes(4, 'big'))
        ct += 1
    return res[:klen]


def za_compute(IDA: bytes, PA: Tuple[int,int]) -> bytes:
    ENTLA = len(IDA) * 8
    a_b = a.to_bytes(32,'big')
    b_b = b.to_bytes(32,'big')
    xG_b = Gx.to_bytes(32,'big'); yG_b = Gy.to_bytes(32,'big')
    xA_b = PA[0].to_bytes(32,'big'); yA_b = PA[1].to_bytes(32,'big')
    msg = ENTLA.to_bytes(2,'big') + IDA + a_b + b_b + xG_b + yG_b + xA_b + yA_b
    return sm3_hash(msg)


def deterministic_k(pri: int, h1: bytes, extra: bytes = b'') -> int:
    # key: bytes of x (private) and optionally extra data
    x = pri.to_bytes(32, 'big')
    V = b'\x01' * 32
    K = b'\x00' * 32
    K = hmac_sm3(K, V + b'\x00' + x + h1 + extra)
    V = hmac_sm3(K, V)
    K = hmac_sm3(K, V + b'\x01' + x + h1 + extra)
    V = hmac_sm3(K, V)
    while True:
        T = b''
        while len(T) < 32:
            V = hmac_sm3(K, V)
            T += V
        k = int.from_bytes(T[:32], 'big')
        k = (k % (n-1)) + 1
        if 1 <= k <= n-1:
            return k
        K = hmac_sm3(K, V + b'\x00')
        V = hmac_sm3(K, V)


def sm2_keygen() -> Tuple[int, Tuple[int,int]]:
    d = secrets.randbelow(n-1) + 1
    P = scalar_mul(d, (Gx, Gy))
    return d, P

def sm2_sign(d: int, IDA: bytes, M: bytes, k_func: Optional[Callable]=None) -> Tuple[int,int]:
    # k_func: function(e_bytes, d) -> k int; if None, use random k
    ZA = za_compute(IDA, scalar_mul(d, (Gx,Gy)))
    M_ = ZA + M
    e = sm3_int(M_) % n
    if k_func is None:
        k = secrets.randbelow(n-1) + 1
    else:
        # let k func accept (d, e_bytes)
        k = k_func(d, e.to_bytes(32,'big'))
    while True:
        kG = scalar_mul(k, (Gx, Gy))
        if kG is None:
            k = secrets.randbelow(n-1) + 1
            continue
        x1,_ = kG
        r = (e + x1) % n
        if r == 0 or (r + k) % n == 0:
            k = secrets.randbelow(n-1) + 1
            continue
        inv = inv_mod((1 + d) % n, n)
        s = (inv * (k - r * d)) % n
        if s == 0:
            k = secrets.randbelow(n-1) + 1
            continue
        return (r, s)

def sm2_verify(PA: Tuple[int,int], IDA: bytes, M: bytes, signature: Tuple[int,int]) -> bool:
    r, s = signature
    if not (1 <= r <= n-1 and 1 <= s <= n-1):
        return False
    ZA = za_compute(IDA, PA)
    M_ = ZA + M
    e = sm3_int(M_) % n
    t = (r + s) % n
    if t == 0:
        return False
    x1y1 = point_add(scalar_mul(s, (Gx,Gy)), scalar_mul(t, PA))
    if x1y1 is None:
        return False
    x1,_ = x1y1
    R = (e + x1) % n
    return R == r


if __name__ == "__main__":
    IDA = b'ALICE123@YAHOO.COM'  # example ID
    M = b"Hello SM2 with SM3 and deterministic k"
    d, P = sm2_keygen()
    print("d =", hex(d))
    print("P.x =", hex(P[0]))
    sig1 = sm2_sign(d, IDA, M)
    print("sig (random k):", tuple(hex(x) for x in sig1))
    print("verify:", sm2_verify(P, IDA, M, sig1))


    def k_from_det(d_local, e_bytes):
        return deterministic_k(d_local, e_bytes)
    sig2 = sm2_sign(d, IDA, M, k_func=k_from_det)
    print("sig (det k):", tuple(hex(x) for x in sig2))
    print("verify:", sm2_verify(P, IDA, M, sig2))


    k = secrets.randbelow(n-1) + 1
    def k_fixed(d_local, e_bytes):
        return k
    m1 = b"Message one"
    m2 = b"Message two"
    sig_a = sm2_sign(d, IDA, m1, k_func=k_fixed)
    sig_b = sm2_sign(d, IDA, m2, k_func=k_fixed)
    print("fixed k:", hex(k))
    print("sig_a:", tuple(hex(x) for x in sig_a))
    print("sig_b:", tuple(hex(x) for x in sig_b))

    r1,s1 = sig_a
    r2,s2 = sig_b
    num = (s2 - s1) % n
    den = (s1 + r1 - s2 - r2) % n
    if den % n != 0:
        d_rec = (num * inv_mod(den, n)) % n
        print("recovered d equals:", d_rec == d)
    else:
        print("degenerate case, cannot recover")

