
HASH_NAME=$1
HASH_SIZE=$2
THASH=$3
HASH_OPTION=$4
PARAMS="sphincs-$HASH_NAME-$HASH_SIZE$HASH_OPTION"

make clean
make PARAMS=$PARAMS THASH=$THASH
if (( $? == 0 ))
then
    echo "Make contract succcess"
else
    exit 1
fi


cd tests/sphincsplus_rust
cargo clean
cargo build --examples --no-default-features --features "$HASH_NAME hash_$HASH_SIZE hash_options_$HASH_OPTION thashes_$THASH"
if (( $? == 0 ))
then
    echo "Build test succcess"
else
    exit 1
fi
cd ../../



echo $PARAMS >> benchmark.log
echo $THASH >> benchmark.log
./tests/sphincsplus_rust/target/debug/examples/run_base >> benchmark.log
if (( $? == 0 ))
then
    echo "Run test succcess"
else
    exit 1
fi