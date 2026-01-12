#!/bin/bash


## step 1: verify binary
function verify_binary() {
    get_expected_hash() {
        grep "build/release/c-sphincs-all-in-one-lock$" ../../checksums.txt | awk '{print $1}'
    }

    expected_hash=$(get_expected_hash)

    actual_hash=$(jq -r '.cell_tx.outputs_data[0]' info.json | xxd -r -p | shasum -a 256 | awk '{print $1}')

    if [ "$expected_hash" != "$actual_hash" ]; then
        echo "✗ Binary verification failed!"
        exit 1
    fi
    echo "✓ Binary verification passed!"
}

verify_binary


## step 2: verify lock script

function verify_lock_script() {
    code_hash=$(jq -r '.cell_tx.outputs[0].lock.code_hash' info.json)
    hash_type=$(jq -r '.cell_tx.outputs[0].lock.hash_type' info.json)
    args=$(jq -r '.cell_tx.outputs[0].lock.args' info.json)

    # https://github.com/nervosnetwork/ckb-system-scripts/pull/99#issuecomment-2814285588
    expected_code_hash="0x36c971b8d41fbd94aabca77dc75e826729ac98447b46f91e00796155dddb0d29"
    expected_hash_type="data1"

    if [ "$code_hash" != "$expected_code_hash" ]; then
        echo "✗ code_hash verification failed!"
        exit 1
    fi

    if [ "$hash_type" != "$expected_hash_type" ]; then
        echo "✗ hash_type verification failed!"
        exit 1
    fi
    echo "✓ Lock script verification passed!"

    multisig_output=$(ckb-cli tx build-multisig-address \
    --sighash-address ckb1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqw8jqfpfe9lwsvs74j3a27aalhqshrslps8hlplq \
    --sighash-address ckb1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsq2u7q5rqr3nam68g2wfel9365l855m7fcg58j52a \
    --sighash-address ckb1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsq0m2fr3ygwszxa77l5r7utgku85wyqvjac5wppfj \
    --sighash-address ckb1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqt4q36wdxa34k89g5snyw694jy0nxht8yshfyw55 \
    --sighash-address ckb1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqf4wq9qpe3pk5c0cy0g40mymrf26cqg4qctwdqge \
    --threshold 3 \
    --require-first-n 0 \
    --multisig-code-hash v2)
   
    expected_args=$(echo "$multisig_output" | grep "lock-arg:" | awk '{print $2}')

    if [ "$args" != "$expected_args" ]; then
        echo "✗ Lock args verification failed!"
        echo "  Expected: $expected_args"
        echo "  Actual:   $args"
        exit 1
    fi
    echo "✓ Lock args verification passed!"
}

verify_lock_script

## step 3: verify type script
function verify_type_script() {
    code_hash=$(jq -r '.cell_tx.outputs[0].type.code_hash' info.json)
    hash_type=$(jq -r '.cell_tx.outputs[0].type.hash_type' info.json)
    args=$(jq -r '.cell_tx.outputs[0].type.args' info.json)
    
    # https://github.com/nervosnetwork/rfcs/blob/4b502ffcb02fc7019e0dd4b5f866b5f09819cfbe/rfcs/0024-ckb-genesis-script-list/0024-ckb-genesis-script-list.md#type-id
    expected_code_hash="0x00000000000000000000000000000000000000000000000000545950455f4944"
    expected_hash_type="type"
    
    if [ "$code_hash" != "$expected_code_hash" ]; then
        echo "✗ type script code_hash verification failed!"
        exit 1
    fi
    
    if [ "$hash_type" != "$expected_hash_type" ]; then
        echo "✗ type script hash_type verification failed!"
        exit 1
    fi
    
    echo "✓ Type script verification passed!"
}

verify_type_script
