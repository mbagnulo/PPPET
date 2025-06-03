pragma circom 2.0.0;

/*{
    "P" : [
             [0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1],
             [0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0],
             [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
             [0, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1]
    ],
    "Q" : [
             [1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 0],
             [0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0],
             [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
             [1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0]

    ]
}*/

//INCLUDE APPROPRIATE ADD, SUBTRACT AND MULTIPLY TEMPLATES
include "chunkedmul.circom";
include "chunkedadd.circom";
include "modulus.circom";


// Optimized version, approximately reduces the constraints in half
// The number of constraints in field operations depend on the input size, specially the Modulus
// Turns out performing mod P after every operation is cheaper than only doing it at the end as the final input is much larger

template PointAdd(){

    //Points are represented as tuples (X, Y, Z, T) of extended coordinates, with x = X/Z, y = Y/Z, x*y = T/Z

    var constant_neg_d[3] = [36453506357546404448470858,34096743896386538864219637,13898602798132607198219823];
    var constant_d[3] = [2232119870121729142126755,4588882331281594726377994,24787023429535526392377808];
    var i;
    var base=85;

    signal input P[4][3];
    signal input Q[4][3];
    signal output R[4][3];

    component X1X2 = ChunkedMul(3, 3, base);
    component Y1Y2 = ChunkedMul(3, 3, base);
    component X1Y2 = ChunkedMul(3, 3, base);
    component X2Y1 = ChunkedMul(3, 3, base);
    component T1T2 = ChunkedMul(3, 3, base);
    component Z1Z2 = ChunkedMul(3, 3, base);

    X1X2.in1 <== P[0]; // x1
    X1X2.in2 <== Q[0]; // x2

    Y1Y2.in1 <== P[1]; // y1
    Y1Y2.in2 <== Q[1]; // y2

    X1Y2.in1 <== P[0]; // x1
    X1Y2.in2 <== Q[1]; // y2

    X2Y1.in1 <== Q[0]; // x2
    X2Y1.in2 <== P[1]; // y1

    T1T2.in1 <== P[3]; // t1
    T1T2.in2 <== Q[3]; // t2

    Z1Z2.in1 <== P[2]; // z1
    Z1Z2.in2 <== Q[2]; // z2

    component X1X2_mod = ModulusWith25519Chunked51(6);
    X1X2_mod.in <== X1X2.out;
    component Y1Y2_mod = ModulusWith25519Chunked51(6);
    Y1Y2_mod.in <== Y1Y2.out;
    component X1Y2_mod = ModulusWith25519Chunked51(6);
    X1Y2_mod.in <== X1Y2.out;
    component X2Y1_mod = ModulusWith25519Chunked51(6);
    X2Y1_mod.in <== X2Y1.out;
    component T1T2_mod = ModulusWith25519Chunked51(6);
    T1T2_mod.in <== T1T2.out;
    component Z1Z2_mod = ModulusWith25519Chunked51(6);
    Z1Z2_mod.in <== Z1Z2.out;

    component T1T2d = ChunkedMul(3, 3, base);
    component T1T2neg_d = ChunkedMul(3, 3, base);

    T1T2d.in1 <== T1T2_mod.out;
    T1T2d.in2 <== constant_d;

    T1T2neg_d.in1 <== T1T2_mod.out;
    T1T2neg_d.in2 <== constant_neg_d;

    component T1T2d_mod = ModulusWith25519Chunked51(6);
    T1T2d_mod.in <== T1T2d.out;
    component T1T2neg_d_mod = ModulusWith25519Chunked51(6);
    T1T2neg_d_mod.in <== T1T2neg_d.out;

    
    component e_add = ChunkedAdd(3,2,base);
    component f_add = ChunkedAdd(3,2,base);
    component g_add = ChunkedAdd(3,2,base);
    component h_add = ChunkedAdd(3,2,base);

    e_add.in[0] <== X1Y2_mod.out;
    e_add.in[1] <== X2Y1_mod.out;
    f_add.in[0] <== T1T2neg_d_mod.out;
    f_add.in[1] <== Z1Z2_mod.out;
    g_add.in[0] <== T1T2d_mod.out;
    g_add.in[1] <== Z1Z2_mod.out;
    h_add.in[0] <== X1X2_mod.out;
    h_add.in[1] <== Y1Y2_mod.out;

    component e_mod = ModulusWith25519Chunked51(4);
    e_mod.in <== e_add.out;
    component f_mod = ModulusWith25519Chunked51(4);
    f_mod.in <== f_add.out;
    component g_mod = ModulusWith25519Chunked51(4);
    g_mod.in <== g_add.out;
    component h_mod = ModulusWith25519Chunked51(4);
    h_mod.in <== h_add.out;

    
    component fe = ChunkedMul(3, 3, base);
    component gh = ChunkedMul(3, 3, base);
    component fg = ChunkedMul(3, 3, base);
    component eh = ChunkedMul(3, 3, base);

    fe.in1 <== f_mod.out;
    fe.in2 <== e_mod.out;

    gh.in1 <== g_mod.out;
    gh.in2 <== h_mod.out;

    fg.in1 <== f_mod.out;
    fg.in2 <== g_mod.out;

    eh.in1 <== e_mod.out;
    eh.in2 <== h_mod.out;
    
    component fe_mod = ModulusWith25519Chunked51(6);
    fe_mod.in <== fe.out;
    component gh_mod = ModulusWith25519Chunked51(6);
    gh_mod.in <== gh.out;
    component fg_mod = ModulusWith25519Chunked51(6);
    fg_mod.in <== fg.out;
    component eh_mod = ModulusWith25519Chunked51(6);
    eh_mod.in <== eh.out;
    
    R[0] <== fe_mod.out;
    R[1] <== gh_mod.out;
    R[2] <== fg_mod.out;
    R[3] <== eh_mod.out;
}

/*
template PointAdd(){

    //Points are represented as tuples (X, Y, Z, T) of extended coordinates, with x = X/Z, y = Y/Z, x*y = T/Z

    var constant_neg_d[3] = [36453506357546404448470858,34096743896386538864219637,13898602798132607198219823];
    var constant_d[3] = [2232119870121729142126755,4588882331281594726377994,24787023429535526392377808];
    var i;
    var base=85;

    signal input P[4][3];
    signal input Q[4][3];
    signal output R[4][3];

    component X_1X_2 = ChunkedMul(3, 3, base);
    component Y_1Y_2 = ChunkedMul(3, 3, base);
    component X_1Y_2 = ChunkedMul(3, 3, base);
    component X_2Y_1 = ChunkedMul(3, 3, base);
    component T_1T_2 = ChunkedMul(3, 3, base);
    component Z_1Z_2 = ChunkedMul(3, 3, base);

    for(i=0;i<3;i++){
        X_1X_2.in1[i] <== P[0][i]; // x1
        X_1X_2.in2[i] <== Q[0][i]; // x2

        Y_1Y_2.in1[i] <== P[1][i]; // y1
        Y_1Y_2.in2[i] <== Q[1][i]; // y2
        
        X_1Y_2.in1[i] <== P[0][i]; // x1
        X_1Y_2.in2[i] <== Q[1][i]; // y2
        
        X_2Y_1.in1[i] <== P[1][i]; // y1
        X_2Y_1.in2[i] <== Q[0][i]; // x2

        T_1T_2.in1[i] <== P[3][i]; // t1
        T_1T_2.in2[i] <== Q[3][i]; // t2

        Z_1Z_2.in1[i] <== P[2][i]; // z1
        Z_1Z_2.in2[i] <== Q[2][i]; // z2
    }

    component T_1T_2_d = ChunkedMul(6, 3, base);
    component T_1T_2_neg_d = ChunkedMul(6, 3, base);

    for(i=0;i<2*3;i++){
       T_1T_2_d.in1[i] <== T_1T_2.out[i]; // t1 * t2
       T_1T_2_neg_d.in1[i] <== T_1T_2.out[i]; // t1 * t2
    }

    for(i=0;i<3;i++){
        T_1T_2_d.in2[i] <== constant_d[i];
        T_1T_2_neg_d.in2[i] <== constant_neg_d[i];
    }

    component e_add = ChunkedAdd(6,2,base);
    component f_add = ChunkedAdderIrregular(9,6,base);
    component g_add = ChunkedAdderIrregular(9,6,base);
    component h_add = ChunkedAdd(6,2,base);
    
    for(i=0;i<6;i++){
        e_add.in[0][i] <== X_1Y_2.out[i];
        e_add.in[1][i] <== X_2Y_1.out[i];
        f_add.b[i] <== Z_1Z_2.out[i];  
        g_add.b[i] <== Z_1Z_2.out[i];
        h_add.in[0][i] <== X_1X_2.out[i];
        h_add.in[1][i] <== Y_1Y_2.out[i];  
    }

    for(i=0;i<9;i++){
        f_add.a[i] <== T_1T_2_neg_d.out[i];
        g_add.a[i] <== T_1T_2_d.out[i];
    }

    component final_mul1 = ChunkedMul(10, 7, base);
    component final_mul2 = ChunkedMul(10, 7, base);
    component final_mul3 = ChunkedMul(10, 10, base);
    component final_mul4 = ChunkedMul(7, 7, base);

    for(i=0;i<7;i++){
        final_mul1.in2[i] <== e_add.out[i];
        final_mul2.in2[i] <== h_add.out[i];
        final_mul4.in1[i] <== e_add.out[i];
        final_mul4.in2[i] <== h_add.out[i];
    }

    for(i=0;i<10;i++){
        final_mul1.in1[i] <== f_add.sum[i];
        final_mul2.in1[i] <== g_add.sum[i];
        final_mul3.in1[i] <== f_add.sum[i];
        final_mul3.in2[i] <== g_add.sum[i];
    }

    component final_modulo1 = ModulusWith25519Chunked51(17);
    component final_modulo2 = ModulusWith25519Chunked51(17);
    component final_modulo3 = ModulusWith25519Chunked51(20);
    component final_modulo4 = ModulusWith25519Chunked51(14);

    for(i=0;i<17;i++){
        final_modulo1.in[i] <== final_mul1.out[i];
        final_modulo2.in[i] <== final_mul2.out[i];
    }

    for(i=0;i<20;i++){
        final_modulo3.in[i] <== final_mul3.out[i];
    }

    for(i=0;i<14;i++){
        final_modulo4.in[i] <== final_mul4.out[i];
    }
    
    for(i=0;i<3;i++){
        R[0][i] <== final_modulo1.out[i];
        R[1][i] <== final_modulo2.out[i];
        R[2][i] <== final_modulo3.out[i];
        R[3][i] <== final_modulo4.out[i];    
    } 

    
}
*/

template DoublePt(){
    signal input P[4][3];
    signal output out_2P[4][3];
    component double = PointAdd();
    var i;
    for(i=0;i<3;i++){
        double.P[0][i] <== P[0][i];
        double.P[1][i] <== P[1][i];
        double.P[2][i] <== P[2][i];
        double.P[3][i] <== P[3][i];

        double.Q[0][i] <== P[0][i];
        double.Q[1][i] <== P[1][i];
        double.Q[2][i] <== P[2][i];
        double.Q[3][i] <== P[3][i];
    }
    for(i=0;i<3;i++){
        double.R[0][i] ==> out_2P[0][i];
        double.R[1][i] ==> out_2P[1][i];
        double.R[2][i] ==> out_2P[2][i];
        double.R[3][i] ==> out_2P[3][i];
    }
}
