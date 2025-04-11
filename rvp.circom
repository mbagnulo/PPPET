pragma circom 2.0.0;

include "lib/sk-to-ed25519pk.circom";
include "lib/generate_rendesvouz_cookie.circom";
include "lib/check_merkle_tree.circom";
include "lib/utils.circom";

/* Circuit to verify RVP's policy
 - Prover: HS
 - Verifier: RVP

Clients must compute the rendezvous cookie as follows: H(kp_hs_id | nonce | rvp_onion_key | time_period | period_length)
Nonce provides randomness, the rest of the parameters make the proof valid only for a specific RVP and time period
Client must provide the nonce to the HS through the INTRODUCE1's message
*/

template RVP(rvp_depth){
    signal input ks_hs_id[32]; // Only the first 32 bytes of the 64 bytes expanded format
    signal input rvp_onion_key[32]; // RVP's circuit extension key, aka onion key
    signal input nonce;
    signal input time_period;
    signal input period_length;
    signal input cookie[20];

    // Merkle Tree inputs
    signal input rvp_root;
    signal input rvp_path[rvp_depth];
    signal input rvp_path_indexes[rvp_depth];

    // 1. Compute kp_hs_id from ks_hs_id
    signal kp_hs_id[32];
    component gen_kp = SkToPkEd();
    gen_kp.in <== ks_hs_id;
    kp_hs_id <== gen_kp.out;
    
    // 2. Compute RENDEZVOUS_COOKIE and compare with public input
    component gen_cookie = GenRevCookie();
    gen_cookie.kp_hs_id <== kp_hs_id;
    gen_cookie.nonce <== nonce;
    gen_cookie.rvp_onion_key <== rvp_onion_key;
    gen_cookie.time_period <== time_period;
    gen_cookie.period_length <== period_length;

    component feq = ForceEqualArrays(20);
    feq.array1 <== cookie;
    feq.array2 <== gen_cookie.out;

    // 3. Verify RVP's policy
    component unpack = UnpackBytes(32);
    unpack.bytes <== kp_hs_id;

    component mt = CheckMerkleTree(rvp_depth);
    mt.root <== rvp_root;
    mt.kp_bits <== unpack.bits;
    mt.path <== rvp_path;
    mt.path_indexes <== rvp_path_indexes;
}

component main {public [rvp_root, cookie, rvp_onion_key, time_period, period_length]}= RVP(14);