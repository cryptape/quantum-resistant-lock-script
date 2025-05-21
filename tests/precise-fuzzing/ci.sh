#!/usr/bin/env bash
set -ex

# Note this bash script simply ensures that precise-fuzzing package build
# in all feature configuration, it does not aim to run the fuzzing workflow
# for now.

HASH_NAMES="shake sha2"
HASH_SIZES="128 192 256"
HASH_OPTIONS="f s"
for HASH_NAME in ${HASH_NAMES[@]}; do
  for HASH_SIZE in ${HASH_SIZES[@]}; do
    for HASH_OPTION in ${HASH_OPTIONS[@]}; do
        cargo test \
          -p precise-fuzzing \
          --no-default-features \
          --features "${HASH_NAME}_${HASH_SIZE}${HASH_OPTION}"
        cargo test \
          -p precise-fuzzing-cargo-fuzz \
          --no-default-features \
          --features "${HASH_NAME}_${HASH_SIZE}${HASH_OPTION}"
      done
    done
  done
done
