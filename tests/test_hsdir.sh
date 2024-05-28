#!/bin/bash

circom ../hsdir.circom --r1cs --wasm --sym
snarkjs r1cs info hsdir.r1cs

node hsdir_js/generate_witness.js hsdir_js/hsdir.wasm input_hsdir.json witness.wtns


