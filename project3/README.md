# Project 3: 用 Circom 实现 Poseidon2 哈希电路（n=256, t=3, d=5）并用 Groth16 生成证明

> 公开输入：`hash`（Poseidon2 输出）；隐私输入：`in[0..rate-1]`（哈希原像）。本项目只考虑 **1 个 block**（t=3 → rate=2）。
> 依托开源库 **circomlib** 的 Poseidon2 组件实现（参数默认 d=5），满足“二次开发”要求。

## 目录结构
```
project3_poseidon2/
├─ circuits/
│  └─ poseidon2_verify.circom       # 主电路（计算 Poseidon2 并约束等于公共输入 hash）
├─ input/
│  └─ input.json                    # 示例输入（两个私有字段元素、以及公共 hash 由 witness 计算导出）
├─ scripts/
│  ├─ setup_groth16.sh              # 一键编译 & 生成 Groth16 证明系统（Linux/WSL/Mac）
│  ├─ setup_groth16.bat             # Windows 批处理版本
│  ├─ prove.sh                      # 生成 witness、proof、verify（Linux/WSL/Mac）
│  └─ prove.bat                     # Windows 批处理版本
└─ README.md
```

## 数学与参数说明
- 选用 **t=3**：1 个 capacity，2 个 rate → 1 个 block 可容纳 2 个字段元素输入；
- 指数 **d=5**（Poseidon2 推荐参数）；
- 场为 BN254（Circom 默认 `Fr`，位数约 254，接近题目 n=256）。
- Sponge 结构：
  1. `state = [in[0], in[1], 0]`（capacity 初始化为 0）；
  2. 经过 Poseidon2 置换（若干轮常量 + MDS + Sbox^5）；
  3. 输出 `state[0]` 作为 `hash`；
- 公开输入：`hash`，私有输入：`in[0], in[1]`。约束：`poseidon2([in0, in1]) == hash`。

> 备注：题目允许“依托开源项目二次开发”。本实现调用 circomlib 的 Poseidon2 组件以确保常量与参数正确。

## 环境依赖
- Node.js >= 16
- circom 编译器（v2）：https://docs.circom.io
- snarkjs：`npm i -g snarkjs`
- circomlib（包含 Poseidon2）：在项目根目录安装：
  ```bash
  npm init -y
  npm i circomlib
  ```


## 快速开始（Groth16）
### 1) 编译电路
```bash
circom circuits/poseidon2_verify.circom --r1cs --wasm --sym -o build
```

### 2) Powers of Tau（通用预设）
```bash
snarkjs powersoftau new bn128 17 pot17_0000.ptau -v
snarkjs powersoftau contribute pot17_0000.ptau pot17_0001.ptau --name="first" -v
```

### 3) 生成 zkey
```bash
snarkjs groth16 setup build/poseidon2_verify.r1cs pot17_0001.ptau poseidon2_0000.zkey
snarkjs zkey contribute poseidon2_0000.zkey poseidon2_0001.zkey --name="1st contribution" -v
snarkjs zkey export verificationkey poseidon2_0001.zkey verification_key.json
```

### 4) 生成 witness（示例输入见 `input/input.json`）
```bash
node build/poseidon2_verify_js/generate_witness.js build/poseidon2_verify_js/poseidon2_verify.wasm input/input.json witness.wtns
```

### 5) 生成与验证证明
```bash
snarkjs groth16 prove poseidon2_0001.zkey witness.wtns proof.json public.json
snarkjs groth16 verify verification_key.json public.json proof.json
```

### 6) 导出以太坊验证合约（可选）
```bash
snarkjs zkey export solidityverifier poseidon2_verifier.sol poseidon2_0001.zkey
```

## 输入说明
`input/input.json`：
```json
{
  "in": ["1", "2"]
}
```
- 这两个是 **私有输入**（哈希原像）。
- `hash` 为 **公开输入**，无需手写；witness 计算后会在 `public.json` 里出现。

## 说明：为何选择 circomlib
Poseidon2 需要**严格的常量（MDS、轮常量）**和**精确流程**，手写容易出错。采用 circomlib 的标准实现可保证参数正确，并满足“(n,t,d)=(256,3,5)”的要求（circomlib 以 BN254 场实现，d=5；t=3 为常用配置）。

## 参考
- Poseidon2 论文：https://eprint.iacr.org/2023/323.pdf
- circom 文档：https://docs.circom.io/
- circomlib（iden3）：https://github.com/iden3/circomlib
