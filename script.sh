#!/bin/bash

circom check_blinded_key.circom --r1cs --wasm --sym
snarkjs r1cs info check_blinded_key.r1cs

node check_blinded_key_js/generate_witness.js check_blinded_key_js/check_blinded_key.wasm input.json witness.wtns


