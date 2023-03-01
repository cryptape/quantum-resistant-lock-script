# quantum-resistant-lock-script
Qantum resistant lock script on CKB, using SPHINCS+

## SPHINCS+

## Build

### Compile contract
``` shell
make all-via-docker
```

### Compile other hash type
``` shell
make all-via-docker PARAMS=sphincs-shake-256f THASH=robust
```
Different hash types will have large performance differences when verifying. For specific performance differences, please refer to the table below. You can also refer to this script to generate and execute contracts (tests/sphincsplus_rust/run_example.sh).


## Performance
Use items for tests/sphincsplus/optimization/run-all-optimization.sh.
The script uses fixed signature data (tests/sphincsplus/test_data/), Because different signature data will have subtle differences.

|               |  128s bit  |  128f bit  |  192s bit  |  192f bit  |  256s bit  |  256f bit  |
| ------------- | ---------- | ---------- | ---------- | ---------- | ---------- | ---------- |
|   pubkey size |       32   |       32   |       48   |       48   |       64   |       64   |
|     sign size |     7888   |    17120   |    16256   |    35696   |    29824   |    49888   |
|  shake simple |    16.9M   |    49.6M   |    25.4M   |    73.8M   |    37.1M   |    72.4M   |
|  shake robust |    34.3M   |    98.4M   |    49.1M   |   147.5M   |    73.2M   |   150.3M   |
|   sha2 simple |    10.7M   |    33.9M   |    16.8M   |    48.7M   |    24.7M   |    47.5M   |
|   sha2 robust |    22.5M   |    64.5M   |    34.1M   |    98.6M   |    60.4M   |   130.3M   |
| haraka simple |    27.5M   |    73.9M   |    39.2M   |   105.8M   |    60.4M   |   114.9M   |
| haraka robust |    45.7M   |   119.8M   |    70.5M   |   182.7M   |   102.8M   |   193.3M   |

* Note: Default hash type: **shake-128f-simple** (Verify cycles: about 70M)

## Sample

```shell
tx init --tx-file tx.json
wallet get-capacity --address ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqfkmqr3ry0crq4w88n86mk4h99am3dlldsuydg36
wallet get-live-cells --address ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqfkmqr3ry0crq4w88n86mk4h99am3dlldsuydg36
tx add-input --tx-hash 0x1ff88a5f9cb719abd86978b05c39d82fd83473519272013afdbee20d5c7ff162 --index 1 --tx-file tx.json
tx add-output --to-sighash-address ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqfkmqr3ry0crq4w88n86mk4h99am3dlldsuydg36 --capacity 15096.20139385 --tx-file tx.json
```
