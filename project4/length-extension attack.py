import struct
import os

def rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

def P0(x):
    return x ^ rotl(x, 9) ^ rotl(x, 17)

def P1(x):
    return x ^ rotl(x, 15) ^ rotl(x, 23)

def FF(a, b, c, j):
    if j < 16:
        return a ^ b ^ c
    else:
        return (a & b) | (a & c) | (b & c)

def GG(e, f, g, j):
    if j < 16:
        return e ^ f ^ g
    else:
        return (e & f) | ((~e) & g)

def sm3(message: bytes) -> bytes:
    IV = [0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
          0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E]
    T = [0x79CC4519] * 16 + [0x7A879D8A] * 48
    
    orig_len = len(message)
    msg_len = orig_len * 8
    message += b'\x80'
    while (len(message) % 64) != 56:
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
        
        registers = [(r ^ s) & 0xFFFFFFFF for r, s in zip(registers, [A, B, C, D, E, F, G, H])]
    
    return b''.join(struct.pack('>I', r) for r in registers)

def sm3_with_iv(message: bytes, iv: bytes) -> bytes:
    registers = list(struct.unpack('>8I', iv))
    
    msg_len = len(message) * 8
    padded = message + b'\x80'
    while (len(padded) % 64) != 56:
        padded += b'\x00'
    padded += struct.pack('>Q', msg_len)
    
    for i in range(0, len(padded), 64):
        block = padded[i:i+64]
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
        

        registers = [(r ^ s) & 0xFFFFFFFF for r, s in zip(registers, [A, B, C, D, E, F, G, H])]
    
    return b''.join(struct.pack('>I', r) for r in registers)


def generate_padding(secret_len: int) -> bytes:
    padding = b'\x80'
    padding += b'\x00' * ((56 - (secret_len + 1) % 64) % 64
    padding += struct.pack('>Q', secret_len * 8)
    return padding


def length_extension_attack(original_hash: bytes, secret_len: int, malicious: bytes) -> bytes:
    """
    执行长度扩展攻击
    
    参数:
        original_hash: 原始消息的哈希值 (bytes)
        secret_len: 原始秘密消息的长度 (int)
        malicious: 要追加的恶意消息 (bytes)
    
    返回:
        扩展后消息的哈希值 (bytes)
    """
    # 生成原始消息的填充
    padding = generate_padding(secret_len)
    
    # 使用原始哈希作为IV计算扩展哈希
    new_hash = sm3_with_iv(padding + malicious, original_hash)
    
    return new_hash


def verify_attack():
    # 生成随机秘密消息
    secret = os.urandom(32)
    print(f"[+] 原始秘密: {secret.hex()} (长度: {len(secret)} 字节)")
    

    orig_hash = sm3(secret)
    print(f"[+] 原始哈希: {orig_hash.hex()}")
    
   
    malicious = b"__malicious_payload__"
    print(f"[+] 恶意扩展: {malicious.decode()}")
    
    
    new_hash = length_extension_attack(orig_hash, len(secret), malicious)
    print(f"[+] 攻击哈希: {new_hash.hex()}")
    
 
    padding = generate_padding(len(secret))
    real_hash = sm3(secret + padding + malicious)
    print(f"[+] 真实哈希: {real_hash.hex()}")
    

    if new_hash == real_hash:
        print("\n[+] 长度扩展攻击成功!")
        print(f"   攻击生成的哈希与真实哈希匹配: {new_hash.hex()}")
    else:
        print("\n[-] 攻击失败: 哈希值不匹配")
        print(f"   攻击哈希: {new_hash.hex()}")
        print(f"   真实哈希: {real_hash.hex()}")

if __name__ == "__main__":
   
    global T
    T = [0x79CC4519] * 16 + [0x7A879D8A] * 48
    
    print("SM3 长度扩展攻击演示")
    print("=" * 50)
    verify_attack()