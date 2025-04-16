pragma circom 2.0.0;

include "merkle_tree/tree.circom";
include "circomlib/poseidon.circom";
include "circomlib/bitify.circom";
include "utils.circom";

// Checks if kp_hs_id is in Allowed List
// If not, returns error
template CheckMerkleTree(depth){
    signal input root;
    signal input key[32];
    signal input path_indexes[depth];
    signal input path[depth];

    // We first obtain kp_hs_id as an int (we can't hash arrays of 256 elements with Poseidon)
    signal kp_int;
    component unpack = UnpackBytes(32);
    unpack.bytes <== key;
    component b2n = Bits2Num(256);
    b2n.in <== unpack.bits;
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
    component feq = ForceEqual();
    feq.in[0] <== root;
    feq.in[1] <== out_root;
}