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
mkdir -p corpus
./fuzzer -max_len=80000 -workers=2 -jobs=2 corpus
