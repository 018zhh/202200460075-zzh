pragma circom 2.0.0;

include "circomlib/poseidon.circom"; 

template Poseidon2(n, t, d) {
    signal input in[t];
    signal output out;
    
    component mds = MdsMatrix(t);
    for (var i = 0; i < t; i++) {
        mds.in[i] <== in[i];
    }

    component poseidon = Poseidon(n, t, d);
    for (var i = 0; i < t; i++) {
        poseidon.inputs[i] <== mds.out[i];
    }
    out <== poseidon.out;
}

component main {public [in]} = Poseidon2(256, 3, 5);