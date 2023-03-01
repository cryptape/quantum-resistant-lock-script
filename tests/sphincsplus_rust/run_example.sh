if [ ! -n "$1" ] ;then
  HASH_NAME="shake"
  HASH_SIZE="128"
  THASH="simple"
  HASH_OPTION="f"
else
  HASH_NAME=$1
  HASH_SIZE=$2
  THASH=$3
  HASH_OPTION=$4
fi
PARAMS="sphincs-$HASH_NAME-$HASH_SIZE$HASH_OPTION"

#!/bin/bash
workdir=$(
  cd $(dirname $0)/../../
  pwd
)

cd $workdir

rm -rf build/*
mkdir -p build

make all-via-docker PARAMS=$PARAMS THASH=$THASH > /dev/null
if (($? != 0)); then
  exit 1
fi

cd tests/sphincsplus_rust
cargo clean > /dev/null
cargo build --examples --no-default-features --features "$HASH_NAME hash_$HASH_SIZE hash_options_$HASH_OPTION thashes_$THASH" > /dev/null  2>&1
./target/debug/examples/run_base
if (($? != 0)); then
  exit 1
fi
