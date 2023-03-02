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
|signature size |     7888   |    17120   |    16256   |    35696   |    29824   |    49888   |
|  shake simple |    16.9M   |    49.6M   |    25.4M   |    73.8M   |    37.1M   |    72.4M   |
|  shake robust |    34.3M   |    98.4M   |    49.1M   |   147.5M   |    73.2M   |   150.3M   |
|   sha2 simple |    10.7M   |    33.9M   |    16.8M   |    48.7M   |    24.7M   |    47.5M   |
|   sha2 robust |    22.5M   |    64.5M   |    34.1M   |    98.6M   |    60.4M   |   130.3M   |
| haraka simple |    27.5M   |    73.9M   |    39.2M   |   105.8M   |    60.4M   |   114.9M   |
| haraka robust |    45.7M   |   119.8M   |    70.5M   |   182.7M   |   102.8M   |   193.3M   |

* Note: Default hash type: **shake-128f-simple** (Verify cycles: about 70M)

## Sample in Dev Blockchain
**Convert a default Lock to ckb-sphincsplus lock script (in ckb dev)**

1. compile. Hera we use the default options.
   </br>
   Here we will get a sphincsplus_lock file, the size is about 85608bytes.
2. Deploy the compiled contract to the test network.
   </br>
   We use [ckb-cli](https://github.com/nervosnetwork/ckb-cli) to deploy this contract, You can refer to [here](https://github.com/nervosnetwork/ckb-cli/wiki/Handle-Complex-Transaction#a-demo).
   * After the execution is successful, it is recommended to record the tx-hash to facilitate subsequent operations.
3. Generate key file.
   </br>
   Use this tool: tools/ckb-sphincs-tools.
   ``` shell
   cargo run -- gen-key key.json
   ```
   We can get a set of key files, including public and private keys.
   * If the contract you compile does not use the default value, it needs to be the same here.
   * Need to save this file.
4. Convert a secp256k1 default lock script to SPHINCS+ lock script.
   ``` shell
   cargo run -- cc_to_sphincsplus --tx_hash <tx-hash> --tx_index <index> --key_file key.json --prikey <You can use ckb-cli account export>
   ```
5. Convert a SPHINCS+ lock script to secp256k1 default lock script.
   ``` shell
   cargo run -- cc_to_sphincsplus --tx_hash <tx-hash> --tx_index <index> --key_file key.json --lock_arg <LOCK-ARG> --sp_tx_hash <SPHINCS+ Script in step 2> --sp_tx_index <index>
   ```


## Deployment on testnet
TODO
