
bash ./run_sphincs_plus.sh shake 256 robust f
if (( $? == 0 ))
then
    echo "success"
else
    exit 1
fi
