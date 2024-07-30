pragma circom 2.0.0;

include "merkle_tree/tree.circom";
include "utils.circom";
include "circomlib/poseidon.circom";
include "circomlib/bitify.circom";

// Checks if kp_hs_id is in Allowed List
// If not, returns error
template CheckMerkleTree(depth){
    signal input root;
    signal input kp_bits[256];
    signal input path_indexes[depth];
    signal input path[depth];

    // We first obtain kp_hs_id as an int (we can't hash arrays of 256 elements)
    signal kp_int;
    component b2n = Bits2Num(256);

    b2n.in <== kp_bits;
    kp_int <== b2n.out;

    // Hash kp_int (if kp_hs_dir is in the allowed list, it should be a node in the Merkle Tree)
    component poseidon = Poseidon(1);
    poseidon.inputs[0] <== kp_int;
    signal kp_node <== poseidon.out;
    
    component merkle_tree = MerkleTreeInclusionProof(depth);
    merkle_tree.leaf <== kp_node;
    merkle_tree.pathIndices <== path_indexes;
    merkle_tree.siblings <== path;

    signal out_root <== merkle_tree.root;

    // Check that the calculated root is the same as the input root
    component a = ForceEqual();
    a.in[0] <== root;
    a.in[1] <== out_root;
}


// component main {public [root]} = CheckMerkleTree(2);