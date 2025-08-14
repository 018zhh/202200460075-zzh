import struct

def sm3(message: bytes) -> bytes:
    IV = [0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
          0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E]
    T = [0x79CC4519] * 16 + [0x7A879D8A] * 48

    msg_len = len(message) * 8
    message += b'\x80'
    while (len(message) * 8) % 512 != 448:
        message += b'\x00'
    message += struct.pack('>Q', msg_len)

    registers = IV.copy()
    for i in range(0, len(message), 64):
        block = message[i:i+64]
        W = list(struct.unpack('>16I', block)) + [0] * 52
        for j in range(16, 68):
            W[j] = P1(W[j-16] ^ W[j-9] ^ rotl(W[j-3], 15)) ^ rotl(W[j-13], 7) ^ W[j-6]
        W_prime = [W[j] ^ W[j+4] for j in range(64)]

        A, B, C, D, E, F, G, H = registers
        for j in range(64):
            SS1 = rotl((rotl(A, 12) + E + rotl(T[j], j)) & 0xFFFFFFFF, 7)
            SS2 = SS1 ^ rotl(A, 12)
            TT1 = (FF(A, B, C, j) + D + SS2 + W_prime[j]) & 0xFFFFFFFF
            TT2 = (GG(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF
            D = C
            C = rotl(B, 9)
            B = A
            A = TT1
            H = G
            G = rotl(F, 19)
            F = E
            E = P0(TT2)

        registers = [(x ^ y) & 0xFFFFFFFF for x, y in zip(registers, [A, B, C, D, E, F, G, H])]

    return b''.join(struct.pack('>I', x) for x in registers)

def rotl(x, n): return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
def P0(x): return x ^ rotl(x, 9) ^ rotl(x, 17)
def P1(x): return x ^ rotl(x, 15) ^ rotl(x, 23)
def FF(a, b, c, j): return a ^ b ^ c if j < 16 else (a & b) | (a & c) | (b & c)
def GG(e, f, g, j): return e ^ f ^ g if j < 16 else (e & f) | ((~e) & g)