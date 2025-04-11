pragma circom 2.0.0;

// From hash_circuits, for cases in we need these subcircuits but don't need SHA3

template ToBits(n) {
  signal input  inp;
  signal output out[n];

  var sum = 0;
  for(var i=0; i<n; i++) {
    out[i] <-- (inp >> i) & 1;
    out[i] * (1-out[i]) === 0;
    sum += (1<<i) * out[i];
  }

  inp === sum;
}

template UnpackBytes(n) {
  signal input  bytes[n];
  signal output bits[8*n];

  component tobits[n];

  for(var j=0; j<n; j++) {
    tobits[j] = ToBits(8);
    tobits[j].inp <== bytes[j];
    for(var i=0; i<8; i++) {
      tobits[j].out[i] ==> bits[ j*8 + i ];
    }
  }
}

template PackBytes(n) {
  signal input  bits[8*n];
  signal output bytes[n];

  for(var k=0; k<n; k++) {
    var sum = 0;
    for(var i=0; i<8; i++) {
      sum += bits[ 8*k + i ] * (1<<i);
    }
    bytes[k] <== sum;
  }
}
  