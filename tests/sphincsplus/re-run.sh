#!/bin/bash
workdir=$(
  cd $(dirname $0)/../../
  pwd
)

cd $workdir

rm -rf build/*
mkdir -p build

make -f tests/sphincsplus/Makefile
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
