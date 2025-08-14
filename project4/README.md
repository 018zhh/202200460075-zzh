# Project 4：SM3 软件实现与优化（结合课堂 PPT）+ 长度扩展攻击 + RFC6962 Merkle 树

> 目标：
> - `sm3_ref.py`：**基础实现**（严格遵循 GM/T 0004-2012，结构清晰、便于对照 PPT 推导）
> - `sm3_opt.py`：**软件优化实现**（结合 PPT 的优化策略：常量缓存、循环展开、就地消息扩展、减少内存分配/拷贝、批量处理接口等）
> - `sm3_numba.py`：**JIT 优化（Numba）** 可选项（若安装了 numba，可获得明显加速）
> - `simd/sm3_avx2.c`：**SIMD/AVX2 模板**（示例性实现与注释，展示如何把 32 轮并行化；含简单 Makefile 与 Python 封装示例 `sm3_hw.py`）
> - `length_extension_attack.py`：**长度扩展攻击演示**
> - `merkle_rfc6962.py`：**RFC6962 风格** Merkle 树（10 万叶可跑），含存在性/不存在性证明与验证
> - `bench.py`：**基准测试**（基础版 vs 优化版 vs Numba/JIT，如可用）

---

## 一、数学与算法要点（与课堂 PPT 对应）

1. **压缩函数 CF 与消息扩展**  
   - 初始向量 `IV` 8×32bit；
   - 消息填充：`m || 0x80 || 0x00... || len(m)_64bits`，使得比特长度 ≡ 448 (mod 512)；
   - 消息扩展生成 `W[0..67]` 与 `W'[0..63]`，其中：  
     `W[i] = P1(W[i-16] ⊕ W[i-9] ⊕ (W[i-3]≪15)) ⊕ (W[i-13]≪7) ⊕ W[i-6]`（i=16..67）  
     `W'[i] = W[i] ⊕ W[i+4]`（i=0..63）  
   - 轮常量：`Tj = 0x79CC4519 (j<16), 0x7A879D8A (j≥16)`；
   - 轮函数：  
     `SS1 = ((A≪12) + E + (Tj≪j))≪7`，`SS2 = SS1 ⊕ (A≪12)`  
     `TT1 = FF(A,B,C,j) + D + SS2 + W'[j]`  
     `TT2 = GG(E,F,G,j) + H + SS1 + W[j]`  
     其中 `FF`/`GG` 为两段式布尔函数（j<16 与 j≥16 不同）。

2. **软件优化策略**
   - **常量预计算/缓存**：`Tj`、循环中 `(A≪12)` 重用；
   - **就地消息扩展**：复用 `W/W'` 数组，避免重复分配；
   - **循环展开**：在 Python 层适度展开（保持可读性），在 C/AVX2 中可 4 步或 8 步展开；
   - **减少内存拷贝**：尽量在 `int` 与 `bytes` 间原地转换；
   - **批量接口**：一次性处理多块消息，减少函数调度开销（见 `sm3_opt.batch_hash`）；
   - **JIT/Numba**：将核心循环转换为 JIT 编译以获得近似 C 的速度；
   - **SIMD/AVX2**：提供模板展示并行 4× 或 8× block 的方法（示例代码与注释，便于后续扩展）。

---

## 二、目录结构

```
project4_sm3_ppt/
├─ sm3_ref.py                    # 基础实现（教学版）
├─ sm3_opt.py                    # 软件优化实现（批量接口 + 轻量展开）
├─ sm3_numba.py                  # Numba/JIT 版本（可选）
├─ sm3_hw.py                     # Python 层硬件封装：若编译了 simd/sm3_avx2.c，可调用
├─ simd/
│  ├─ sm3_avx2.c                 # AVX2 并行模板（示例、含注释）
│  └─ Makefile                   # 生成 sm3_avx2.so（Linux/WSL/Mac）
├─ length_extension_attack.py    # 长度扩展攻击演示（中文输出）
├─ merkle_rfc6962.py             # RFC6962 风格 Merkle 树（存在性/不存在性证明）
├─ bench.py                      # 基准测试脚本（可选择实现进行对比）
└─ README.md
```

---

## 三、快速开始
```bash
python bench.py                       # 基准测试（基础/优化/Numba 若可用）
python length_extension_attack.py     # 演示长度扩展攻击
python merkle_rfc6962.py              # 构建 Merkle 树与证明验证（默认 50,000 叶，可改 100,000）
```

> 可选：如要体验 AVX2 版本（Linux/WSL/Mac 且有 AVX2）：
> ```bash
> cd simd && make && cd ..
> python -c "import sm3_hw; print('has_avx2:', sm3_hw.has_avx2())"
> ```

---

## 四、实验小结

- **性能**：在 Python 层通过常量缓存、就地扩展与批量处理，`sm3_opt` 相比参考实现可获得 **1.3×~2×** 的速度提升；Numba/JIT 可进一步获得 **2×+**（视平台而定）。
- **安全性**：SM3 属于 Merkle–Damgård 结构，天然支持长度扩展攻击；工程中建议使用 **HMAC-SM3** 或在协议层封装长度。
- **可扩展性**：RFC6962 的叶/结点前缀（0x00/0x01）避免二义性；替换底层哈希为 SM3 可复用 CT 的审计证明流程。
- **工程化**：示例给出了从 Python 优化 → JIT → SIMD 的“分层思路”，便于逐步落地更高性能实现。
