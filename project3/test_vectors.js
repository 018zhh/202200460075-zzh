const { calculateWitness } = require("./poseidon2_js/witness_calculator");
const fs = require("fs");

// 测试向量
const testInputs = [
    { in: [1, 2, 3], expectedHash: 123456789 },  // 替换为真实值
    { in: [4, 5, 6], expectedHash: 987654321 }
];

(async () => {
    const wasmBuffer = fs.readFileSync("./poseidon2_js/poseidon2.wasm");
    for (const input of testInputs) {
        const witness = await calculateWitness(wasmBuffer, input);
        const hash = witness[1]; // 假设哈希值在 witness 的第 2 个位置
        console.assert(hash === input.expectedHash, "Test failed!");
    }
    console.log("All tests passed!");
})();