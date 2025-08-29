#!/usr/bin/env bash

workdir=$(
  cd $(dirname $0)
  pwd
)

cd $workdir

HASH_NAMES="shake sha2"
HASH_SIZES="128 192 256"
HASH_OPTIONS="f s"
THASHS="simple"
for HASH_NAME in ${HASH_NAMES[@]}; do
  for HASH_SIZE in ${HASH_SIZES[@]}; do
    for HASH_OPTION in ${HASH_OPTIONS[@]}; do
      for THASH in ${THASHS[@]}; do
        echo $HASH_NAME-$HASH_SIZE$HASH_OPTION $THASH

        TOP="${TOP:-$workdir/../..}" cargo test \
          --no-default-features \
          --features "$HASH_NAME hash_$HASH_SIZE hash_options_$HASH_OPTION thashes_$THASH"
        if (($? == 0)); then
          echo "success"
        else
          exit 1
        fi
      done
    done
  done
done
