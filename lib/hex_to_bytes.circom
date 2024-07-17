pragma circom 2.0.0;

include "circomlib/comparators.circom";
include "circomlib/bitify.circom";

/* Takes a string hex sequence encoded with ASCII and transforms it to its actual byte value
    E.g.: "A3" -> ASCII -> [65, 51] -> HexToBytes() -> 163
*/

// Converts a character into its corresponding number (e.g., "A" -> ASCII -> 65 -> CharToNum -> 10)
template CharToNum(){
    signal input in;
    signal output out;

   // Check if the character is in [0-9]
   component le_1 = LessThan(8);
    le_1.in[0] <== in;
    le_1.in[1] <== 57+1;

    component ge_1 = GreaterThan(8);
    ge_1.in[0] <== in;
    ge_1.in[1] <== 48-1;

    signal range_num <== ge_1.out * le_1.out;
    signal sum_num <== range_num * (in - 48);

   // Check if the character is in [A-F]
   component le_2 = LessThan(8);
    le_2.in[0] <== in;
    le_2.in[1] <== 70+1;

    component ge_2 = GreaterThan(8);
    ge_2.in[0] <== in;
    ge_2.in[1] <== 65-1;
    
    signal range_AZ <== ge_2.out * le_2.out;
    signal sum_AZ <== sum_num + range_AZ * (in - 55);
   
    // Check if the character is in [a-f]
    component le_3 = LessThan(8);
    le_3.in[0] <== in;
    le_3.in[1] <== 102+1;

    component ge_3 = GreaterThan(8);
    ge_3.in[0] <== in;
    ge_3.in[1] <== 97-1;
    
    signal range_az <== ge_3.out * le_3.out;
    out <== sum_AZ + range_az * (in - 87);

    // Check that the input is a valid character
    1 === range_num + range_AZ + range_az;

}

// Joins 2 chars and outputs the byte value
// E.g. [10, 3] (A3) --> JoinChars -->  163
template JoinChars(){
    signal input in[2];
    signal output out;

    signal char1_bits[4];
    signal char2_bits[4];

    component n2b_1 = Num2Bits(4);
    component n2b_2 = Num2Bits(4);

    n2b_1.in <== in[0];
    n2b_2.in <== in[1];

    signal bits[8];
    var j = 0;

    for (var i = 0; i < 4; i++){
        bits[j] <== n2b_2.out[i];
        j++;
    }

    for (var i = 0; i < 4; i++){
        bits[j] <== n2b_1.out[i];
        j++;
    }

    component b2n = Bits2Num(8);
    b2n.in <== bits;

    out <== b2n.out;
}

template HexToBytes(size){
    signal input in[size];
    signal output out[size/2];

    assert((size % 2) == 0);

    component ctn[size];
    component jc[size/2];

    var j = 0;
    for (var i = 0; i < size; i+=2){
        ctn[i] = CharToNum();
        ctn[i+1] = CharToNum();

        ctn[i].in <== in[i];
        ctn[i+1].in <== in[i+1];

        jc[j] = JoinChars();
        jc[j].in[0] <== ctn[i].out;
        jc[j].in[1] <== ctn[i+1].out;

        out[j] <== jc[j].out;
        j++;
    }

}

//component main = HexToBytes(6);