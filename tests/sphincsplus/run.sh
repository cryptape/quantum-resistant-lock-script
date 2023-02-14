workdir=$(
  cd $(dirname $0)/../../
  pwd
)

mkdir -p build

cd $workdir
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
