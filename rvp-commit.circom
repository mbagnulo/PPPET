pragma circom 2.0.0;

include "lib/sk-to-ed25519pk.circom";
include "lib/check_proof_commitment.circom";

// TODO: Add comments

template RVP(){
    signal input ed_sk[32];
    signal input bj_x;
    signal input bj_y;
    signal input nonce;

    signal input proof_commitment;

    // Calculate ed25519 public key
    component pk = SkToPkEd();
    pk.in <== ed_sk;

    // Create commitment and compare
    component check_commitment = CheckProofCommitment();
    check_commitment.commitment <== proof_commitment;
    check_commitment.rvp_ed_key <== pk.out;
    check_commitment.rvp_jubjub_x <== bj_x;
    check_commitment.rvp_jubjub_y <== bj_y;
    check_commitment.nonce <== nonce;
}

component main {public [proof_commitment]} = RVP();
