pragma circom 2.0.0;

include "merkle_tree/tree.circom";
include "utils.circom";
include "circomlib/poseidon.circom";
include "circomlib/bitify.circom";

/* Slightly adjusted version to work with hsdir_zkf.circom */

template CheckMerkleTree_ZKF(depth){
    signal input root;
    signal input key[2];
    signal input path_indexes[depth];
    signal input path[depth];

    signal kp_leaf;
    component poseidon = Poseidon(2);
    poseidon.inputs[0] <== key[0];
    poseidon.inputs[1] <== key[1];
    kp_leaf <== poseidon.out;

    component merkle_tree = MerkleTreeInclusionProof(depth);
    merkle_tree.leaf <== kp_leaf;
    merkle_tree.pathIndices <== path_indexes;
    merkle_tree.siblings <== path;

    signal out_root <== merkle_tree.root;

    // Check that the calculated root is the same as the input root
    component feq = ForceEqual();
    feq.in[0] <== root;
    feq.in[1] <== out_root;
}