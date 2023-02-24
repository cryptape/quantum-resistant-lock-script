workdir=$(
  cd $(dirname $0)
  pwd
)

cd $workdir

HASH_NAMES="shake sha2 haraka"
HASH_SIZES="128 256"
HASH_OPTIONS="s"
THASHS="simple robust"
for HASH_NAME in ${HASH_NAMES[@]}; do
  for HASH_SIZE in ${HASH_SIZES[@]}; do
    for HASH_OPTION in ${HASH_OPTIONS[@]}; do
      for THASH in ${THASHS[@]}; do
        PARAMS="sphincs-$HASH_NAME-$HASH_SIZE$HASH_OPTION"
        echo "-----------------------------------------------"
        echo $PARAMS $THASH

        make clean > /dev/null
        make all-via-docker PARAMS=$PARAMS THASH=$THASH > /dev/null
        ckb-debugger --bin build/verify --max-cycles=10000000000
        
        if (($? == 0)); then
          echo "success"
        else
          exit 1
        fi

      done
    done
  done
done
