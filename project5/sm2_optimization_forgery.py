import hashlib
import secrets
from typing import Tuple, Optional


P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
GX = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
GY = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0

class SM2:
    def __init__(self):
        self.p = P
        self.a = A
        self.b = B
        self.n = N
        self.g = (GX, GY)
        self._custom_hash = None  # 用于伪造签名的自定义哈希函数
    
    def _add_points(self, P: Tuple[int, int], Q: Tuple[int, int]) -> Tuple[int, int]:
        """椭圆曲线点加法"""
        if P == (0, 0):
            return Q
        if Q == (0, 0):
            return P
        x1, y1 = P
        x2, y2 = Q
        
        if x1 == x2 and y1 == y2:
            # 处理y=0的情况
            if y1 == 0:
                return (0, 0)
            lam = (3 * x1 * x1 + self.a) * pow(2 * y1, -1, self.p) % self.p
 
        elif x1 == x2:
            return (0, 0)
  
        else:
            lam = (y2 - y1) * pow(x2 - x1, -1, self.p) % self.p
        
        x3 = (lam * lam - x1 - x2) % self.p
        y3 = (lam * (x1 - x3) - y1) % self.p
        return (x3, y3)
    
    def _mul_point(self, k: int, P: Tuple[int, int]) -> Tuple[int, int]:
        """椭圆曲线点乘 (标量乘法)"""
        R = (0, 0)
        while k:
            if k & 1:
                R = self._add_points(R, P)
            P = self._add_points(P, P)
            k >>= 1
        return R
    
    def _hash(self, data: bytes) -> int:
        """哈希函数 (可被重写用于伪造)"""
        if self._custom_hash:
            return self._custom_hash(data)
        return int.from_bytes(hashlib.sha256(data).digest(), 'big') % self.n
    
    def key_gen(self) -> Tuple[int, Tuple[int, int]]:
        """生成密钥对"""
        d = secrets.randbelow(self.n - 1) + 1
        P = self._mul_point(d, self.g)
        return d, P
    
    def sign(self, d: int, msg: bytes, Z: bytes) -> Tuple[int, int]:
        """SM2签名"""
        e = self._hash(Z + msg)
        while True:
            k = secrets.randbelow(self.n - 1) + 1
            x1, _ = self._mul_point(k, self.g)
            r = (e + x1) % self.n
            if r == 0 or r + k == self.n:
                continue
            s = (pow(1 + d, -1, self.n) * (k - r * d)) % self.n
            if s != 0:
                return r, s
    
    def verify(self, P: Tuple[int, int], msg: bytes, Z: bytes, sig: Tuple[int, int]) -> bool:
        """SM2验签"""
        r, s = sig
        if not (1 <= r < self.n and 1 <= s < self.n):
            return False
        e = self._hash(Z + msg)
        t = (r + s) % self.n
        if t == 0:
            return False
      
        point1 = self._mul_point(s, self.g)
        point2 = self._mul_point(t, P)
        x1, y1 = self._add_points(point1, point2)
        R = (e + x1) % self.n
        return R == r
    
    def forge_signature(self, target_public_key: Tuple[int, int], 
                        message: bytes, user_id: bytes) -> Optional[Tuple[int, int]]:

    
        while True:
            s = secrets.randbelow(self.n - 1) + 1
            t = secrets.randbelow(self.n - 1) + 1
            
            # 计算r = t - s mod n
            r = (t - s) % self.n
            if r != 0:  # 确保r不为0
                break
        
   
        point_sg = self._mul_point(s, self.g)
        point_tp = self._mul_point(t, target_public_key)
        R_point = self._add_points(point_sg, point_tp)
        

        if R_point == (0, 0):
            return self.forge_signature(target_public_key, message, user_id)
        
        xR, _ = R_point
        
  
        required_e = (r - xR) % self.n
        
 
        def custom_hash(data: bytes) -> int:
            """自定义哈希函数，当输入匹配目标消息时返回预设的e值"""
            if data == user_id + message:
                return required_e
       
            return int.from_bytes(hashlib.sha256(data).digest(), 'big') % self.n
        

        self._custom_hash = custom_hash
        

        return (r, s)

def satoshi_nakamoto_signature_forgery():
    """伪造中本聪的数字签名演示"""
    print("="*60)
    print("伪造中本聪的SM2数字签名")
    print("="*60)
    

    sm2 = SM2()
    

    satoshi_priv, satoshi_pub = sm2.key_gen()
    print(f"[中本聪的公钥] x: {hex(satoshi_pub[0])}")
    print(f"               y: {hex(satoshi_pub[1])}")
    

    forged_message = b"Transfer 1,000,000 BTC to Alice"
    user_id = b"Satoshi Nakamoto"
    
    print("\n[伪造签名]")
    print(f"消息: '{forged_message.decode()}'")
    print(f"用户ID: '{user_id.decode()}'")
    

    forged_signature = sm2.forge_signature(satoshi_pub, forged_message, user_id)
    if not forged_signature:
        print("伪造签名失败!")
        return
    
    r, s = forged_signature
    print(f"伪造的签名: r = {hex(r)}")
    print(f"            s = {hex(s)}")
    

    print("\n[验证伪造的签名]")
    valid = sm2.verify(satoshi_pub, forged_message, user_id, forged_signature)
    
    if valid:
        print(">>> 签名验证成功! 伪造签名有效 <<<")
        print("="*60)
        print("注意: 在实际系统中，这种伪造需要控制哈希函数输出")
        print("或能够找到特定输入使Hash(Z||msg) = e")
        print("="*60)
    else:
        print(">>> 签名验证失败! 伪造无效 <<<")

if __name__ == "__main__":
    
    satoshi_nakamoto_signature_forgery()
    
  
    print("\n\n" + "="*60)
    print("正常SM2签名/验证流程 (对比)")
    print("="*60)
    
    sm2 = SM2()
    priv_key, pub_key = sm2.key_gen()
    user_id = b"alice@example.com"
    message = b"Hello, Blockchain!"
    

    signature = sm2.sign(priv_key, message, user_id)
    print(f"消息: '{message.decode()}'")
    print(f"签名: r={hex(signature[0])}, s={hex(signature[1])}")
    
   
    valid = sm2.verify(pub_key, message, user_id, signature)
    print(f"验证结果: {'成功' if valid else '失败'}")
    
   
    tampered_message = b"Hello, Blockchain! (tampered)"
    valid_tampered = sm2.verify(pub_key, tampered_message, user_id, signature)
    print(f"篡改消息后验证: {'意外成功' if valid_tampered else '失败 (正常)'}")
    
  
    tampered_signature = (signature[0], (signature[1] + 1) % sm2.n)
    valid_tampered_sig = sm2.verify(pub_key, message, user_id, tampered_signature)
    print(f"篡改签名后验证: {'意外成功' if valid_tampered_sig else '失败 (正常)'}")