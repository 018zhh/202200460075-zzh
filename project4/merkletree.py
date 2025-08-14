import struct
import os
import math
from bisect import bisect_left

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
            w16 = W[j-16]
            w9 = W[j-9]
            w3 = rotl(W[j-3], 15)
            w13 = rotl(W[j-13], 7)
            W[j] = P1(w16 ^ w9 ^ w3) ^ w13 ^ W[j-6]
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

class MerkleTree:
    def __init__(self, data_list: list):
        self.leaf_count = len(data_list)
        self.leaves = [sm3(b'\x00' + data) for data in data_list]
        self.tree = []
        self.build_tree()
    
    def build_tree(self):
        current_level = self.leaves.copy()
        self.tree.append(current_level)
        
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i+1] if i+1 < len(current_level) else left
                parent = sm3(b'\x01' + left + right)
                next_level.append(parent)
            self.tree.append(next_level)
            current_level = next_level
    
    def root(self) -> bytes:
        return self.tree[-1][0]
    
    def get_inclusion_proof(self, index: int) -> list:
        if index < 0 or index >= self.leaf_count:
            raise ValueError("Invalid leaf index")
        
        proof = []
        current_index = index
        
        for level in range(0, len(self.tree) - 1):
            level_nodes = self.tree[level]
            
            if current_index % 2 == 1:
                sibling_index = current_index - 1
            else:
                sibling_index = current_index + 1 if current_index + 1 < len(level_nodes) else current_index
            
            proof.append(level_nodes[sibling_index])
            
            current_index //= 2
        
        return proof
    
    def verify_inclusion(self, data: bytes, index: int, proof: list) -> bool:
        current_hash = sm3(b'\x00' + data)
        
        current_index = index
        for sibling_hash in proof:
            if current_index % 2 == 1:
                current_hash = sm3(b'\x01' + sibling_hash + current_hash)
            else:
                current_hash = sm3(b'\x01' + current_hash + sibling_hash)
            current_index //= 2
        
        return current_hash == self.root()
    
    def get_exclusion_proof(self, data: bytes) -> tuple:
        target_hash = sm3(b'\x00' + data)
        
        leaf_hashes = [leaf.hex() for leaf in self.leaves]
        target_hex = target_hash.hex()
        
        pos = bisect_left(leaf_hashes, target_hex)
        
        left_index = pos - 1 if pos > 0 else None
        right_index = pos if pos < self.leaf_count else None
        
        left_proof = self.get_inclusion_proof(left_index) if left_index is not None else []
        right_proof = self.get_inclusion_proof(right_index) if right_index is not None else []
        
        return (pos, left_proof, right_proof)
    
    def verify_exclusion(self, data: bytes, pos: int, 
                         left_proof: list, right_proof: list) -> bool:
        target_hash = sm3(b'\x00' + data)
        target_hex = target_hash.hex()
        leaf_hashes = [leaf.hex() for leaf in self.leaves]
        
        if pos < 0 or pos > self.leaf_count:
            return False
        
        if pos > 0:
            left_index = pos - 1
            left_data = b"left_neighbor"
            if not self.verify_inclusion(left_data, left_index, left_proof):
                return False
            
            if leaf_hashes[left_index] >= target_hex:
                return False
        
        if pos < self.leaf_count:
            right_index = pos
            right_data = b"right_neighbor"
            if not self.verify_inclusion(right_data, right_index, right_proof):
                return False
            
            if leaf_hashes[right_index] <= target_hex:
                return False
        
        return True

def test_merkle_tree():
    print("生成100,000个叶子节点...")
    data_list = [os.urandom(32) for _ in range(100000)]
    
    print("构建Merkle树...")
    merkle_tree = MerkleTree(data_list)
    print(f"Merkle根: {merkle_tree.root().hex()}")
    print(f"树高度: {len(merkle_tree.tree)}")
    
    print("\n测试存在性证明:")
    test_index = 50000
    test_data = data_list[test_index]
    proof = merkle_tree.get_inclusion_proof(test_index)
    print(f"叶子 {test_index} 的证明路径长度: {len(proof)}")
    
    is_valid = merkle_tree.verify_inclusion(test_data, test_index, proof)
    print(f"存在性证明验证: {'成功' if is_valid else '失败'}")
    
    print("\n测试不存在性证明:")
    non_existent_data = os.urandom(32)
    while non_existent_data in data_list:
        non_existent_data = os.urandom(32)
    
    pos, left_proof, right_proof = merkle_tree.get_exclusion_proof(non_existent_data)
    print(f"插入位置: {pos}")
    print(f"左证明长度: {len(left_proof)}")
    print(f"右证明长度: {len(right_proof)}")
    
    is_valid = merkle_tree.verify_exclusion(non_existent_data, pos, left_proof, right_proof)
    print(f"不存在性证明验证: {'成功' if is_valid else '失败'}")

if __name__ == "__main__":
    test_merkle_tree()