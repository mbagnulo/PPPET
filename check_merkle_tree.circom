pragma circom 2.0.0;

include "lib/merkle_tree/tree.circom";
include "lib/circomlib/poseidon.circom";
include "lib/hash_circuits/keccak/sha3_bytes.circom"; // Just for UnpackBytes()
include "lib/circomlib/bitify.circom";



template CheckMerkleTree(depth){
    signal input root; // Root of the merkle tree
    signal input kp_bytes[32]; // kp_hs_dir in bytes
    signal input path_indexes[depth]; // Path selector to choose which direction to hash
    signal input path[depth]; // Path to the root

    signal kp_bits[256];
    signal kp_int;
    signal output out;

    // We first obtain kp_bytes as an int (we can't hash arrays of 32 elements)

    /* 
    TODO: We could do this in the main circuit and then pass it as inputs to
    CheckBlindedKey() and CheckMerkleTree() to avoid converting kp_bytes to bits
    twice
    */

    component unpack = UnpackBytes(32);
    component b2n = Bits2Num(256);
    unpack.bytes <== kp_bytes;
    kp_bits <== unpack.bits;
    b2n.in <== kp_bits;
    kp_int <== b2n.out;

    // Hash kp_int (if kp_hs_dir is in the allowed list, it should be a node in the Merkle Tree)
    component poseidon = Poseidon(1);
    poseidon.inputs[0] <== kp_int;
    signal kp_node <== poseidon.out;
    
    component merkle_tree = MerkleTreeInclusionProof(depth); // 2 levels in this case, change accordingly
    merkle_tree.leaf <== kp_node;
    merkle_tree.pathIndices <== path_indexes;
    merkle_tree.siblings <== path;

    signal out_root <== merkle_tree.root;

    // Check that the calculated root is the same as the input root
    root === out_root;
}


component main {public [root]} = CheckMerkleTree(2);