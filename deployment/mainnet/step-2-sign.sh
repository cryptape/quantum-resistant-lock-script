#!/bin/bash

ckb-cli deploy sign-txs \
    --from-account ckb1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqw9zyl653xlmzkkwmkguk0sqxkalkyat8suxxefv \
    --add-signatures \
    --info-file info.json
