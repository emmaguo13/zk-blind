#!/bin/bash

CIRCUIT_DIR=./circuits/jwt_benchmarks
TIME=(gtime -f "mem %M\ntime %e\ncpu %P")
CIRCUIT_NAME=jwt
BUILD_DIR="./build/$CIRCUIT_NAME"

avg_time() {
    #
    # usage: avg_time n command ...
    #
    n=$1; shift
    (($# > 0)) || return                   # bail if no command given
    echo "$@"
    for ((i = 0; i < n; i++)); do
        "${TIME[@]}" "$@" 2>&1
    done | awk '
        /mem/ { mem = mem + $2; nm++ }
        /time/ { time = time + $2; nt++ }
        /cpu/  { cpu  = cpu  + substr($2,1,length($2)-1); nc++}
        END    {
                 if (nm>0) printf("mem %f\n", mem/nm);
                 if (nt>0) printf("time %f\n", time/nt);
                 if (nc>0) printf("cpu %f\n",  cpu/nc)
               }'
}

function normalProve() {
  # pushd "$CIRCUIT_DIR"
  avg_time 1 snarkjs groth16 prove "$BUILD_DIR"/jwt_single1.zkey "$BUILD_DIR"/witness.wtns "$BUILD_DIR"/proof.json "$BUILD_DIR"/public.json
  proof_size=$(ls -lh "$BUILD_DIR"/proof.json | awk '{print $5}')
  echo "Proof size: $proof_size"
  # popd
}

function verify() {
  # pushd "$CIRCUIT_DIR"
  avg_time 1 snarkjs groth16 verify "$BUILD_DIR"/verification_key.json "$BUILD_DIR"/public.json "$BUILD_DIR"/proof.json
  # popd
}

echo "========== Step1: prove  =========="
normalProve

echo "========== Step2: verify  =========="
verify
