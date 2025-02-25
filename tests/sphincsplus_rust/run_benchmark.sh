#!/usr/bin/env bash

workdir=$(
  cd $(dirname $0)
  pwd
)

if [ ! -n "$1" ] ;then
  HASH_NAME="shake"
  HASH_SIZE="256"
  THASH="simple"
  HASH_OPTION="f"
else
  HASH_NAME=$1
  HASH_SIZE=$2
  THASH=$3
  HASH_OPTION=$4
fi

export TOP="${TOP:-$workdir/../..}"

cd $TOP
make build
if (($? == 0)); then
  echo "make success"
else
  exit 1
fi

cd $workdir
cargo build --no-default-features --features "serialize_key $HASH_NAME hash_$HASH_SIZE hash_options_$HASH_OPTION thashes_$THASH"
cd $TOP
echo $HASH_NAME-$HASH_SIZE$HASH_OPTION $THASH
./target/debug/run_brenchmark `./target/debug/generate_fix_infos`
if (($? == 0)); then
  echo "success"
else
  exit 1
fi
