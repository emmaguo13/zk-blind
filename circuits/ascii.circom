pragma circom 2.1.4;
include "../node_modules/circomlib/circuits/comparators.circom";

// only converts ascii to numbers from 0-9
template AsciiToNum (max_input) {
    signal input in[max_input];
    signal output out;

    var temp = in[0] - 48;

    for (var i = 1; i < max_input; i++) {
        temp *= 10;
        temp += in[i] - 48;
    }

    out <== temp;
}