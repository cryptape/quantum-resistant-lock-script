echo "" > benchmark.log

# shake f

bash ./benchmark.sh shake 128 robust f
if (( $? == 0 ))
then
    echo "success"
else
    exit 1
fi
echo "" >> benchmark.log

bash ./benchmark.sh shake 192 robust f
if (( $? == 0 ))
then
    echo "success"
else
    exit 1
fi
echo "" >> benchmark.log

bash ./benchmark.sh shake 256 robust f
if (( $? == 0 ))
then
    echo "success"
else
    exit 1
fi
echo "" >> benchmark.log

# shake s

bash ./benchmark.sh shake 128 robust s
if (( $? == 0 ))
then
    echo "success"
else
    exit 1
fi
echo "" >> benchmark.log

bash ./benchmark.sh shake 192 robust s
if (( $? == 0 ))
then
    echo "success"
else
    exit 1
fi
echo "" >> benchmark.log

bash ./benchmark.sh shake 256 robust s
if (( $? == 0 ))
then
    echo "success"
else
    exit 1
fi
echo "" >> benchmark.log

# sha2 f

bash ./benchmark.sh sha2 128 robust f
if (( $? == 0 ))
then
    echo "success"
else
    exit 1
fi
echo "" >> benchmark.log

bash ./benchmark.sh sha2 192 robust f
if (( $? == 0 ))
then
    echo "success"
else
    exit 1
fi
echo "" >> benchmark.log

bash ./benchmark.sh sha2 256 robust f
if (( $? == 0 ))
then
    echo "success"
else
    exit 1
fi
echo "" >> benchmark.log

# sha2 s

bash ./benchmark.sh sha2 128 robust s
if (( $? == 0 ))
then
    echo "success"
else
    exit 1
fi
echo "" >> benchmark.log

bash ./benchmark.sh sha2 192 robust s
if (( $? == 0 ))
then
    echo "success"
else
    exit 1
fi
echo "" >> benchmark.log

bash ./benchmark.sh sha2 256 robust s
if (( $? == 0 ))
then
    echo "success"
else
    exit 1
fi
echo "" >> benchmark.log

# haraka f

bash ./benchmark.sh haraka 128 robust f
if (( $? == 0 ))
then
    echo "success"
else
    exit 1
fi
echo "" >> benchmark.log

bash ./benchmark.sh haraka 192 robust f
if (( $? == 0 ))
then
    echo "success"
else
    exit 1
fi
echo "" >> benchmark.log

bash ./benchmark.sh haraka 256 robust f
if (( $? == 0 ))
then
    echo "success"
else
    exit 1
fi
echo "" >> benchmark.log

# haraka s

bash ./benchmark.sh haraka 128 robust s
if (( $? == 0 ))
then
    echo "success"
else
    exit 1
fi
echo "" >> benchmark.log

bash ./benchmark.sh haraka 192 robust s
if (( $? == 0 ))
then
    echo "success"
else
    exit 1
fi
echo "" >> benchmark.log

bash ./benchmark.sh haraka 256 robust s
if (( $? == 0 ))
then
    echo "success"
else
    exit 1
fi
echo "" >> benchmark.log