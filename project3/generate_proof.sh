
circom poseidon2.circom --r1cs --wasm

snarkjs groth16 setup poseidon2.r1cs pot12.ptau poseidon2.zkey
snarkjs zkey export verificationkey poseidon2.zkey verification_key.json

node generate_witness.js poseidon2.wasm input.json witness.wtns

snarkjs groth16 prove poseidon2.zkey witness.wtns proof.json public.json

snarkjs groth16 verify verification_key.json public.json proof.json