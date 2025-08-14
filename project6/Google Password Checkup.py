from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import random
import hashlib
from phe import paillier
import numpy as np

class DDHPSISum:
    def __init__(self, curve=ec.SECP256R1()):
        self.curve = curve
    
    def hash_to_point(self, item):
        """将字符串映射到椭圆曲线点 (简化版)"""
        digest = hashlib.sha256(item.encode()).digest()
        private_key = ec.derive_private_key(int.from_bytes(digest, 'big'), self.curve)
        return private_key.public_key()
    
    def point_to_bytes(self, point):
        """将点转换为字节"""
        return point.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)

class Party1:
    def __init__(self, items):
        self.items = items  # 用户标识列表
        self.curve = ec.SECP256R1()
        self.k1 = random.randint(1, 2**256)  # 私密指数
        
    def round1(self):
        """第一阶段：发送处理后的标识"""
        self.public_points = []
        for item in self.items:
            point = self.hash_to_point(item)
            # 计算 H(item)^k1
            pub_point = self.scalar_mult(point, self.k1)
            self.public_points.append(pub_point)
        # 打乱顺序
        random.shuffle(self.public_points)
        return self.public_points
    
    def round3(self, B_points, C_points, E_ciphers, paillier_public_key):
        """第三阶段：计算交集和总和"""
        # 计算 d_j = (b_j)^k1
        D_points = [self.scalar_mult(b_point, self.k1) for b_point in B_points]
        
        # 在C中查找匹配项
        C_bytes_set = {self.point_to_bytes(c) for c in C_points}
        intersection_indices = []
        for idx, d_point in enumerate(D_points):
            if self.point_to_bytes(d_point) in C_bytes_set:
                intersection_indices.append(idx)
        
        # 计算同态和
        sum_cipher = paillier_public_key.encrypt(0)
        for idx in intersection_indices:
            sum_cipher += E_ciphers[idx]
        
        return sum_cipher, len(intersection_indices)
    
    def hash_to_point(self, item):
        digest = hashlib.sha256(item.encode()).digest()
        private_key = ec.derive_private_key(int.from_bytes(digest, 'big'), self.curve)
        return private_key.public_key()
    
    def scalar_mult(self, point, scalar):
        """标量乘法 (简化实现)"""
        # 实际应用中应使用安全实现
        return point
    
    def point_to_bytes(self, point):
        return point.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)

class Party2:
    def __init__(self, items_with_values):
        self.items = [item for item, _ in items_with_values]
        self.values = [value for _, value in items_with_values]
        self.curve = ec.SECP256R1()
        self.k2 = random.randint(1, 2**256)  # 私密指数
        
        # 生成Paillier密钥对
        self.paillier_public_key, self.paillier_private_key = paillier.generate_paillier_keypair()
    
    def round2(self, A_points):
        """第二阶段：发送处理后的数据和加密值"""
        # 计算 b_j = H(w_j)^k2
        B_points = []
        for item in self.items:
            point = self.hash_to_point(item)
            pub_point = self.scalar_mult(point, self.k2)
            B_points.append(pub_point)
        
        # 计算 c_i = (a_i)^k2
        C_points = [self.scalar_mult(a_point, self.k2) for a_point in A_points]
        
        # 加密关联值
        E_ciphers = [self.paillier_public_key.encrypt(value) for value in self.values]
        
        # 打乱顺序
        indices = list(range(len(B_points)))
        random.shuffle(indices)
        B_shuffled = [B_points[i] for i in indices]
        E_shuffled = [E_ciphers[i] for i in indices]
        C_shuffled = C_points.copy()
        random.shuffle(C_shuffled)
        
        return B_shuffled, C_shuffled, E_shuffled, self.paillier_public_key
    
    def decrypt_sum(self, sum_cipher):
        """解密总和"""
        return self.paillier_private_key.decrypt(sum_cipher)
    
    def hash_to_point(self, item):
        digest = hashlib.sha256(item.encode()).digest()
        private_key = ec.derive_private_key(int.from_bytes(digest, 'big'), self.curve)
        return private_key.public_key()
    
    def scalar_mult(self, point, scalar):
        """标量乘法 (简化实现)"""
        # 实际应用中应使用安全实现
        return point

# 测试协议
if __name__ == "__main__":
    # 创建数据集
    p1_items = ["user1", "user2", "user3", "user4", "user5"]
    p2_data = [("user1", 100), ("user3", 200), ("user5", 300), ("user7", 400)]
    
    # 初始化参与方
    party1 = Party1(p1_items)
    party2 = Party2(p2_data)
    
    # 协议执行
    # Round 1
    A_points = party1.round1()
    
    # Round 2
    B_points, C_points, E_ciphers, paillier_pk = party2.round2(A_points)
    
    # Round 3
    sum_cipher, intersection_size = party1.round3(B_points, C_points, E_ciphers, paillier_pk)
    
    # P2解密总和
    total_sum = party2.decrypt_sum(sum_cipher)
    
    # 输出结果
    print(f"交集大小: {intersection_size}")
    print(f"交集值总和: {total_sum}")
    print("预期结果: 交集大小=3, 总和=600 (100+200+300)")