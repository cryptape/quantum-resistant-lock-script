if [ ! -n "$1" ] ;then
  PARAMS="sphincs-shake-256f"
  THASH="robust"
else
  HASH_NAME=$1
  HASH_SIZE=$2
  THASH=$3
  HASH_OPTION=$4
  PARAMS="sphincs-$HASH_NAME-$HASH_SIZE$HASH_OPTION"
fi

#!/bin/bash
workdir=$(
  cd $(dirname $0)/../../
  pwd
)

cd $workdir

rm -rf build/*
mkdir -p build

make -f tests/sphincsplus/Makefile PARAMS=$PARAMS THASH=$THASH
if (($? == 0)); then
  echo "make success"
else
  exit 1
fi

./build/test_sphincsplus
if (($? == 0)); then
  echo "success"
else
  exit 1
fi
