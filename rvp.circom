pragma circom 2.0.0;

include "lib/sk-to-ed25519pk.circom";
include "lib/generate_rendezvous_cookie.circom";
include "lib/check_merkle_tree.circom";
include "lib/utils.circom";

/* 

Clients must compute the rendezvous cookie as follows: H(kp_hs_id | rvp_id_fingerprint | time_period | period_length | nonce)
Nonce provides randomness, the rest of the parameters make the proof valid only for a specific RVP and time period
Client must provide the nonce to the HS through the INTRODUCE1's message

If using an allowlist (is_blocklist = 0):
- The circuit verifies if kp_hs_id is in the tree. 
- Leaf is calculated as H(lo(kp_hs_id), hi(kp_hs_id))
- low_key and high_key are ignored

If using a blocklist (is_blocklist = 1):
- The circuit verifies if low_key is in the tree
- Leaf is calculated as H(lo(low_key), hi(high_key), lo(high_key), hi(high_key))
- Verifies that low_key < kp_hs_id < high_key

*/

template RVP(depth){
    signal input ks_hs_id[32]; // Only the first 32 bytes of the 64 bytes expanded format
    signal input root;
    signal input path[depth];
    signal input path_indexes[depth];

    signal input nonce;
    signal input time_period;
    signal input time_period_length;
    signal input rvp_id_fingerprint; // Identity fingerprint (SHA-1 of its legacy RSA identity key) of the RVP as an integer. Included in INTRODUCE1's link specifiers.
    signal input cookie[20];

    signal input low_key[32];
    signal input high_key[32];
    signal input is_blocklist;

    // 1. Check input correctness
    // path_indexes = 0 or 1 is checked inside tree logic
    component range_check[4];
    range_check[0] = CheckRangeBytes(20);
    range_check[0].in <== cookie;

    for (var i = 1; i < 4; i++){
        range_check[i] = CheckRangeBytes(32);
    }

    range_check[1].in <== ks_hs_id;
    range_check[2].in <== low_key;
    range_check[3].in <== high_key;

    component n2b = Num2Bits(160);
    n2b.in <== rvp_id_fingerprint;

    0 === is_blocklist * (1 - is_blocklist);

    // 2. Compute kp_hs_id from ks_hs_id
    signal kp_hs_id[32];
    component gen_kp = SkToPkEd();
    gen_kp.in <== ks_hs_id;
    kp_hs_id <== gen_kp.out;

    // 3. Divide keys into two 128 bits limbs.
    // Needed for comparisons, leaf calculation, etc.
    component k2n[3];
    for (var i = 0; i < 3; i++){
        k2n[i] = KeyToNum();
    }

    k2n[0].in <== kp_hs_id;
    signal kp_hs_id_halves[2] <== k2n[0].out;

    k2n[1].in <== low_key;
    signal low_key_halves[2] <== k2n[1].out;

    k2n[2].in <== high_key;
    signal high_key_halves[2] <== k2n[2].out;

    // 4. If blocklist, verify that low_key < kp_hs_id < high_key
    component lt[2];
    lt[0] = LessThan256();
    lt[0].a <== low_key_halves;
    lt[0].b <== kp_hs_id_halves;

    lt[1] = LessThan256();
    lt[1].a <== kp_hs_id_halves;
    lt[1].b <== high_key_halves;

    0 === is_blocklist * (1 - lt[0].out);
    0 === is_blocklist * (1 - lt[1].out);

    // 5. Check allowlist / blocklist
    component leaf = CalculateLeaf();
    leaf.kp_hs_id <== kp_hs_id_halves;
    leaf.low_key <== low_key_halves;
    leaf.high_key <== high_key_halves;
    leaf.is_blocklist <== is_blocklist;

    component mt = CheckMerkleTree(depth);
    mt.root <== root;
    mt.leaf <== leaf.out;
    mt.path <== path;
    mt.path_indexes <== path_indexes;
    
    // 6. Compute RENDEZVOUS_COOKIE and compare with public input
    component gen_cookie = GenRevCookie();
    gen_cookie.kp_hs_id <== kp_hs_id_halves;
    gen_cookie.rvp_id_fingerprint <== rvp_id_fingerprint;
    gen_cookie.time_period <== time_period;
    gen_cookie.time_period_length <== time_period_length;
    gen_cookie.nonce <== nonce;

    component feq = ForceEqualArrays(20);
    feq.array1 <== cookie;
    feq.array2 <== gen_cookie.out;
}

component main {public [root, cookie, time_period, time_period_length, rvp_id_fingerprint, is_blocklist]} = RVP(14);