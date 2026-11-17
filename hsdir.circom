pragma circom 2.0.0;

include "lib/check_blinded_key.circom";
include "lib/check_merkle_tree.circom";
include "lib/utils.circom";

/*

time_period and time_period_length validity are checked by the HSDir

If using an allowlist (is_blocklist = 0):
- The circuit verifies if kp_hs_id is in the tree. 
- Leaf is calculated as H(lo(kp_hs_id), hi(kp_hs_id))
- low_key and high_key are ignored

If using a blocklist (is_blocklist = 1):
- The circuit verifies if low_key is in the tree
- Leaf is calculated as H(lo(low_key), hi(high_key), lo(high_key), hi(high_key))
- Verifies that low_key < kp_hs_id < high_key 

*/

template HSDir(depth){
    signal input kp_hs_id[32]; // kp_hs_id in bytes

    signal input root;
    signal input path[depth];
    signal input path_indexes[depth];

    signal input kp_base_85[4][3]; // Kp_hs_id in base 2^85
    signal input blinded_key[32]; // Blinded key in bytes
    signal input time_period[8]; // Time period as an array of 8 bytes (big endian)
    signal input time_period_length[8]; // Period length as an array of 8 bytes (big endian)

    signal input low_key[32];
    signal input high_key[32];
    signal input is_blocklist;

    // 1. Check input correctness
    // path_indexes = 0 or 1 is checked inside tree logic
    component range_check[6];

    for(var i = 0; i < 4; i++){
        range_check[i] = CheckRangeBytes(32);
    }

    range_check[0].in <== kp_hs_id;
    range_check[1].in <== blinded_key;
    range_check[2].in <== low_key;
    range_check[3].in <== high_key;

    range_check[4] = CheckRangeBytes(8);
    range_check[5] = CheckRangeBytes(8);
    range_check[4].in <== time_period;
    range_check[5].in <== time_period_length;

    component range_check_base = CheckRangeKeyBase85();
    range_check_base.in <== kp_base_85;

    0 === is_blocklist * (1 - is_blocklist);

    // 2. Divide keys into two 128 bits limbs.
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

    // 3. If blocklist, verify that low_key < kp_hs_id < high_key
    component lt[2];
    lt[0] = LessThan256();
    lt[0].a <== low_key_halves;
    lt[0].b <== kp_hs_id_halves;

    lt[1] = LessThan256();
    lt[1].a <== kp_hs_id_halves;
    lt[1].b <== high_key_halves;

    0 === is_blocklist * (1 - lt[0].out);
    0 === is_blocklist * (1 - lt[1].out);

    // 4. Check allowlist / blocklist
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

    // 5. Compute blinded key and compare with public input
    // kp_hs_id === kp_base_85 is checked here
    component gen_bkey = GenerateBlindedKey();
    gen_bkey.kp_hs_id <== kp_hs_id;
    gen_bkey.kp_base_85 <== kp_base_85;
    gen_bkey.period_number <== time_period;
    gen_bkey.period_length <== time_period_length;

    component feq = ForceEqualArrays(32);
    feq.array1 <== blinded_key;
    feq.array2 <== gen_bkey.out;
}

component main {public [root, blinded_key, time_period, time_period_length, is_blocklist]} = HSDir(14);
