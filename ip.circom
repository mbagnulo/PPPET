pragma circom 2.0.0;

include "lib/utils.circom";
include "lib/sk-to-ed25519pk.circom";
include "lib/check_merkle_tree.circom";
include "lib/generate_policy_cookie.circom";

/*

Tor stores ks_hs_id in the 64 bytes expanded format, i.e. SHA512(seed).  
For this circuit, we only need to pass the first 32 bytes since we are only deriving the public key

time_period and time_period_length validity are checked by the IP

If using an allowlist (is_blocklist = 0):
- The circuit verifies if kp_hs_id is in the tree. 
- Leaf is calculated as H(lo(kp_hs_id), hi(kp_hs_id))
- low_key and high_key are ignored

If using a blocklist (is_blocklist = 1):
- The circuit verifies if low_key is in the tree
- Leaf is calculated as H(lo(low_key), hi(high_key), lo(high_key), hi(high_key))
- Verifies that low_key < kp_hs_id < high_key

*/

template IP(depth){
    signal input ks_hs_id[32];
    signal input auth_key[32];
    signal input root;
    signal input path[depth];
    signal input path_indexes[depth];
    signal input time_period;
    signal input time_period_length;
    signal input nonce;
    signal input policy_cookie[32];

    signal input low_key[32];
    signal input high_key[32];
    signal input is_blocklist;

    // 1. Check input correctness
    // path_indexes = 0 or 1 is checked inside tree logic
    component range_check[4];
    for (var i = 0; i < 4; i++){
        range_check[i] = CheckRangeBytes(32);
    }

    range_check[0].in <== ks_hs_id;
    range_check[1].in <== auth_key;
    range_check[2].in <== low_key;
    range_check[3].in <== high_key;

    0 === is_blocklist * (1 - is_blocklist);

    // 2. Compute kp_hs_id from ks_hs_id
    signal kp_hs_id[32];
    component gen_kp = SkToPkEd();
    gen_kp.in <== ks_hs_id;
    kp_hs_id <== gen_kp.out;

    // 3. Divide keys into two 128 bits limbs.
    // Needed for comparisons, leaf calculation, etc.
    component k2n[4];
    for (var i = 0; i < 4; i++){
        k2n[i] = KeyToNum();
    }

    k2n[0].in <== kp_hs_id;
    signal kp_hs_id_halves[2] <== k2n[0].out;

    k2n[1].in <== auth_key;
    signal auth_key_halves[2] <== k2n[1].out;

    k2n[2].in <== low_key;
    signal low_key_halves[2] <== k2n[2].out;

    k2n[3].in <== high_key;
    signal high_key_halves[2] <== k2n[3].out;

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
    
    // 6. Compute POLICY_COOKIE and verify that it is equal to the one passed as an input
    component gen_cookie = GenPolicyCookie();
    gen_cookie.kp_hs_id <== kp_hs_id_halves;
    gen_cookie.auth_key <== auth_key_halves;
    gen_cookie.nonce <== nonce;
    gen_cookie.time_period <== time_period;
    gen_cookie.time_period_length <== time_period_length;

    component feq = ForceEqualArrays(32);
    feq.array1 <== policy_cookie;
    feq.array2 <== gen_cookie.out;
}

component main {public [root, time_period, time_period_length, auth_key, policy_cookie, is_blocklist]} = IP(14);