workdir=$(
  cd $(dirname $0)
  pwd
)

cd $workdir

HASH_NAMES="shake sha2 haraka"
HASH_SIZES="128 192 256"
HASH_OPTIONS="f s"
THASHS="robust simple"
for HASH_NAME in ${HASH_NAMES[@]}; do
  for HASH_SIZE in ${HASH_SIZES[@]}; do
    for HASH_OPTION in ${HASH_OPTIONS[@]}; do
      for THASH in ${THASHS[@]}; do
        echo $HASH_NAME-$HASH_SIZE$HASH_OPTION $THASH

        bash ./run.sh $HASH_NAME $HASH_SIZE $THASH $HASH_OPTION
        
        if (($? == 0)); then
          echo "success"
        else
          exit 1
        fi

      done
    done
  done
done
