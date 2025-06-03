pragma circom 2.0.0;

template Multiplexor2() {
    signal input sel;
    signal input in[2][4][3];
    signal output out[4][3];
    var i;
    for(i=0;i<3;i++){
        out[0][i] <== (in[1][0][i] - in[0][0][i])*sel + in[0][0][i];
        out[1][i] <== (in[1][1][i] - in[0][1][i])*sel + in[0][1][i];
        out[2][i] <== (in[1][2][i] - in[0][2][i])*sel + in[0][2][i];
        out[3][i] <== (in[1][3][i] - in[0][3][i])*sel + in[0][3][i];
    }
}