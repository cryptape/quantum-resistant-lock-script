#!/usr/bin/env bash

workdir=$(
  cd $(dirname $0)
  pwd
)
export TOP="${TOP:-$workdir/../..}"

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

cd $TOP
make build
if (($? != 0)); then
  exit 1
fi

cd $workdir
cargo build --examples --no-default-features --features "$HASH_NAME hash_$HASH_SIZE hash_options_$HASH_OPTION thashes_$THASH" > /dev/null  2>&1
cd $TOP
echo $HASH_NAME-$HASH_SIZE$HASH_OPTION $THASH
./target/debug/examples/run_base
