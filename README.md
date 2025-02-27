# quantum-resistant-lock-script
Quantum resistant lock script on CKB, based on [NIST FIPS 205](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf) standard. 2 implementations exist:

* A C lock script using [SPHINCS+](https://github.com/sphincs/sphincsplus)
* A Rust lock script using [fips205](https://github.com/integritychain/fips205)

## Build

### Compile contract
``` shell
make build
```

The built contracts can be located at `build/release`

### Run all tests
``` shell
make test
```

See [ckb-script-templates](https://github.com/cryptape/ckb-script-templates) for more commands.

The lock script built here uses `all-in-one` mode, meaning one lock script can support all 12 paramter sets defined by NIST FIPS 205 standard. Feel free to also learn about different parameter sets [here](https://github.com/sphincs/sphincsplus#parameters).

See [Simple Usage](./docs/simple.md), or [Advanced Usage](./docs/advanced.md) for usage. Performance discussions are kept in [Performance Doc](./docs/performance.md).

The exact cycle consumptions will slightly vary from one signature to another, a ballpark estimation of cycle consumptions(here we measure cycle consumptions for the whole script, meaning CKB transaction signing is included as well) for each NIST approved parameter set, can be located below(`M` stands for million):

|                      |  128s bit  |  128f bit  |  192s bit  |  192f bit  |  256s bit  |  256f bit  |
| -------------------- | ---------- | ---------- | ---------- | ---------- | ---------- | ---------- |
|   pubkey size        |       32   |       32   |       48   |       48   |       64   |       64   |
|signature size        |     7856   |    17088   |    16224   |    35664   |    29792   |    49856   |
|   sha2 simple (C)    |    11.6M   |    33.5M   |    17.4M   |    49.3M   |    25.5M   |    50.4M   |
|   sha2 simple (Rust) |    21.4M   |    60.2M   |    30.2M   |    89.5M   |    44.1M   |    90.8M   |
|  shake simple (C)    |    19.8M   |    61.3M   |    30.2M   |    91.4M   |    46.0M   |    92.4M   |
|  shake simple (Rust) |    36.1M   |   108.7M   |    53.5M   |   155.0M   |    80.1M   |    166.2M   |

In general, the `s` variants take longer to generate a signature, but takes less cycles to verify. The `f` variants are fast in signature generation but takes longer cycles to verify.

## Tool (Deprecated)

**NOTE**: the following tool shall be considered deprecated, and only kept here for historic reasons.

This tool is to **convert a default Lock(SECP256K1/blake160) to quantum resistant lock script.**. 

Follow steps below:

1. compile.

   By default, sphincsplus_lock file's size is about 85K bytes.
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
4. Convert a SECP256K1/blake160 lock script to quantum resistant lock script.
   ``` shell
   cargo run -- cc_to_sphincsplus --tx_hash <tx-hash> --tx_index <index> --key_file key.json --prikey <You can use ckb-cli account export>
   ```
5. Convert a quantum resistant lock script to SECP256K1/blake160 lock script.
   ``` shell
   cargo run -- cc_to_secp --tx_hash <tx-hash> --tx_index <index> --key_file key.json --lock_arg <LOCK-ARG> --sp_tx_hash <SPHINCS+ Script in step 2> --sp_tx_index <index> --fee 10000
   ```
