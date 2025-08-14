# 实验一：SM4 的软件实现与优化（含 T-Table 与并行）

## 1. 实验目标
- 从 **基础实现** 出发，完成 SM4 的加/解密与密钥扩展；
- 实现 **T-Table 优化** 并对比性能；
- 给出 **并行/向量化思路**：用 NumPy 模拟批量并行（可选：后续用 C/Intrinsics 将 GFNI、VPROLD 引入）；
- 提供 **可执行代码与基准测试**，并验证官方测试向量。

## 2. 算法与数学表示（简要）
- 分组长度：128 bit；轮数：32；密钥：128 bit。
- 记输入分组 4×32bit：X = (X0,X1,X2,X3)。
- 轮函数：F(X0,X1,X2,X3,rk) = X0 ^ L(τ(X1 ^ X2 ^ X3 ^ rk))
  - τ(A)：逐字节 S 盒替换；
  - L(B)=B ⊕ (B<<<2) ⊕ (B<<<10) ⊕ (B<<<18) ⊕ (B<<<24)；
- 输出：逆序 (X35,X34,X33,X32)。

## 3. 代码结构
```
project1_SM4_full/
├── sm4_baseline.py          # 纯 Python 基础实现
├── sm4_ttable.py            # T-Table 优化实现
├── sm4_parallel_numpy.py    # NumPy 批量并行（模拟 SIMD 思路）
├── sm4_simd_template.c      # C/Intrinsics 模板（GFNI/VPROLD/PSHUFB 等）
├── bench.py                 # 跑分脚本
└── README.md
```

## 4. 运行方法
```bash
python sm4_baseline.py
python sm4_ttable.py
python sm4_parallel_numpy.py
python bench.py
```

## 5. 优化策略说明
### 5.1 T-Table
把 τ+L 合并到 4 张表，一轮仅 4 次查表 + 3 次 XOR。

### 5.2 向量化/并行
- **演示实现**：`sm4_parallel_numpy.py` 用向量化批处理 N 个分组，提升吞吐。
- **进一步方向**：`sm4_simd_template.c` 给出 AVX2/AVX-512 接口骨架，可引入
  VPROLD 旋转、GFNI/PSHUFB 字节变换实现 S 盒。


## 5.3 SM4-GCM 工作模式（本实验新增）
GCM = CTR 加密 + GHASH 认证。设：
- 子密钥：\\( H = E_K(0^{128}) \\)
- 初始计数器：\\( J_0 \\)（当 IV 长度为 96 位时，\\( J_0 = IV \parallel 0^{31} \parallel 1 \\)，否则 \\( J_0 = GHASH_H(\emptyset, IV) \\)）
- 计数器块：\\( Ctr_i = inc32(J_0) \\) 连续自增
- 密钥流：\\( S_i = E_K(Ctr_i) \\)
- 密文：\\( C_i = P_i \oplus S_i \\)
- 认证值：\\( S = GHASH_H(A, C) \\)
- 标签：\\( T = E_K(J_0) \oplus S \\)

**实现细节与优化：**
- `sm4_gcm.py` 复用 `sm4_ttable.encrypt_block` 作为块密码；
- CTR 密钥流提供两种生成方式：
  - 纯 Python 按块生成（易读）
  - **NumPy 批量并行** `sm4_ctr_keystream_numpy`（一次生成多块计数器，显著提升吞吐）；
- 提供 `gcm_encrypt/gcm_decrypt` 接口，并在文件末尾附带中文自测。

### 使用方法
```bash
python sm4_gcm.py
```
输出会打印密文与 16 字节标签，并验证解密是否成功。


## 6. 正确性验证
使用标准测试向量：
```
K = 0123456789abcdeffedcba9876543210
P = 0123456789abcdeffedcba9876543210
C = 681edf34d206965e86b3e94f536e4246
```
三份实现均含断言。


## 7. 实验总结
- **正确性**：基础实现、T-Table、并行版以及 GCM 模式均通过自测与标准向量（基础部分）。
- **性能提升**：T-Table 将一轮的 τ+L 融合为查表 + 异或，单块加速明显；对于大数据，NumPy 批处理显著提升吞吐。
- **GCM 设计**：采用 96-bit IV 快速路径、CTR 并行密钥流 + GHASH 认证，接口友好（`gcm_encrypt`/`gcm_decrypt`）。
- **可扩展性**：保留 `sm4_simd_template.c`，后续可引入 AVX2/AVX-512（VPROLD、GFNI、PSHUFB）实现更高性能；也可替换 GHASH 为以 Karatsuba/4-bit table 方式加速。
- **工程化**：`bench.py` 集成所有测试，方便复现实验数据；中文注释完整，适合作业提交与口头展示。


