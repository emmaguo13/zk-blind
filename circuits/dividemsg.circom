pragma circom 2.0.3;

template DivideEncodedMsg(M, logM) {
    signal input posDot;
    signal input str[M];
    signal output pieceA[M];
    signal output pieceB[M];

    signal hasBstarted[M];
    signal isArunning[M];
    component compLE[M], compGE[M];
    for (var i = 0;i < M;i++) {
        compLE[i] = LessThan(logM);
        compLE[i].in[0] <== i;
        compLE[i].in[1] <== posDot;
        isArunning[i] <== compLE[i].out;

        compGE[i] = GreaterThan(logM);
        compGE[i].in[0] <== i;
        compGE[i].in[1] <== posDot;
        hasBstarted[i] <== compGE[i].out;
    }

    for (var i = 0;i < M;i++) {
        pieceA[i] <== isArunning[i] * str[i];
        pieceB[i] <== hasBstarted[i] * str[i];
    }
}
