pragma circom 2.0.0;

include "merkle_tree/tree.circom";
include "circomlib/poseidon.circom";
include "circomlib/bitify.circom";
include "circomlib/mux1.circom";
include "utils.circom";

// Calculates both leaves formats, and chooses one depending on whether we are using an allowlist or a blocklist
// - Allowlist: Leaf = H(key) => H(kp_hs_id)
// - Blocklist: Leaf = H(key, key_next) => H(low_key, high_key)
// All 3 keys are passed represented as two 128 bit halves (lo, hi) represented as integers. This is done since we are working
// in BN254 and we can't operate directly with 256 bit keys.

template CalculateLeaf(){
    signal input kp_hs_id[2];
    signal input low_key[2];
    signal input high_key[2];
    signal input is_blocklist;

    signal output out;

    // Calculate leaf for allow_list, i.e. H(lo(kp_hs_id), hi(kp_hs_id))
    component pAllow = Poseidon(2);
    pAllow.inputs[0] <== kp_hs_id[0];
    pAllow.inputs[1] <== kp_hs_id[1];

    // Calculate leaf for blocklist, i.e. H(lo(low_key), hi(low_key), lo(high_key), hi(high_key))
    component pBlock = Poseidon(4);
    pBlock.inputs[0] <== low_key[0];
    pBlock.inputs[1] <== low_key[1];
    pBlock.inputs[2] <== high_key[0];
    pBlock.inputs[3] <== high_key[1];

    // Choose leaf
    component mux = Mux1();
    mux.c[0] <== pAllow.out;
    mux.c[1] <== pBlock.out;
    mux.s <== is_blocklist;

    out <== mux.out;
}

template CheckMerkleTree(depth){
    signal input root;
    signal input leaf;
    signal input path_indexes[depth];
    signal input path[depth];
   
    component merkle_tree = MerkleTreeInclusionProof(depth);
    merkle_tree.leaf <== leaf;
    merkle_tree.pathIndices <== path_indexes;
    merkle_tree.siblings <== path;

    // Check that the calculated root is the same as the input root
    component feq = ForceEqual();
    feq.in[0] <== root;
    feq.in[1] <== merkle_tree.root;
}