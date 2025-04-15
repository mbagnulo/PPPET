pragma circom 2.0.0;

include "lib/circomlib/babyjub.circom";
include "lib/circomlib/poseidon.circom";
include "lib/circomlib/bitify.circom";
include "lib/check_merkle_tree_zkf.circom";
include "lib/utils.circom";
include "lib/utils_bytes.circom";

template RVP_ZKF(depth){
    signal input ks_hs_id;
    signal input nonce;
    signal input cookie[20];

    signal input root;
    signal input path[depth];
    signal input path_indexes[depth];

    component gen_pk = BabyPbk();
    gen_pk.in <== ks_hs_id;

    signal kp_hs_id_x <== gen_pk.Ax;
    signal kp_hs_id_y <== gen_pk.Ay;

    // Check that kp_hs_id is in Merkle Tree
    component mt = CheckMerkleTree_ZKF(depth);
    mt.root <== root;
    mt.key[0] <== kp_hs_id_x;
    mt.key[1] <== kp_hs_id_y;
    mt.path <== path;
    mt.path_indexes <== path_indexes;

    // Calculate cookie
    component poseidon = Poseidon(3);
    poseidon.inputs[0] <== kp_hs_id_x;
    poseidon.inputs[1] <== kp_hs_id_y;
    poseidon.inputs[2] <== nonce;

    // Truncate output to 20 bytes
    component n2b = Num2Bits_strict();
    n2b.in <== poseidon.out;

    component pack = PackBytes(20);
    for(var i = 0; i < 160; i++){
        pack.bits[i] <== n2b.out[i];
    }

    // Compare with input cookie
    component feq = ForceEqualArrays(20);
    feq.array1 <== cookie;
    feq.array2 <== pack.bytes;
}

component main {public [cookie, root]}= RVP_ZKF(14);