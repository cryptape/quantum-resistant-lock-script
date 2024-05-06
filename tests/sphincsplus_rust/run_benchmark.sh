if [ ! -n "$1" ] ;then
  HASH_NAME="shake"
  HASH_SIZE="256"
  THASH="robust"
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

export BENCH_ARGS=`./target/debug/examples/generate_fix_infos`

cd $workdir
rm -rf build/*
mkdir -p build
make -f Makefile.clang all PARAMS=$PARAMS THASH=$THASH
if (($? == 0)); then
  echo "make success"
else
  exit 1
fi
cd $workdir/tests/sphincsplus_rust
# cargo clean
cargo build --examples --no-default-features --features "serialize_key $HASH_NAME hash_$HASH_SIZE hash_options_$HASH_OPTION thashes_$THASH"
./target/debug/examples/run_brenchmark $BENCH_ARGS
if (($? == 0)); then
  echo "success"
else
  exit 1
fi

cd $workdir
rm -rf build/*
mkdir -p build
make all-via-docker PARAMS=$PARAMS THASH=$THASH
if (($? == 0)); then
  echo "make success"
else
  exit 1
fi
cd $workdir/tests/sphincsplus_rust
cargo build --examples --no-default-features --features "serialize_key $HASH_NAME hash_$HASH_SIZE hash_options_$HASH_OPTION thashes_$THASH"
./target/debug/examples/run_brenchmark $BENCH_ARGS
if (($? == 0)); then
  echo "success"
else
  exit 1
fi
