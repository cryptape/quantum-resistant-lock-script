workdir=$(
  cd $(dirname $0)
  pwd
)

cd $workdir

make all

if (($? == 0)); then
  echo "make success"
else
  exit 1
fi

cd build
./fuzzer
