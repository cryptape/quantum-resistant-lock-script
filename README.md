# quantum-resistant-lock-script
Quantum resistant lock script on CKB, based on [NIST FIPS 205](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf) standard.


There are 3 implementations:
* [A C lock script](./contracts/c-sphincs-all-in-one-lock/) using [SPHINCS+](https://github.com/sphincs/sphincsplus)
* [A Rust lock script](./contracts/sphincs-all-in-one-lock/) using [fips205](https://github.com/integritychain/fips205)
* [A hybrid lock script](./contracts/hybrid-sphincs-all-in-one-lock/) with the implementation of SPHINCS+ utilizing the sphincsplus C library and Rust glue code.

You can find more details about the implementation strategy in [contracts/README.md](./contracts/README.md).

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

|                        |  128s bit  |  128f bit  |  192s bit  |  192f bit  |  256s bit  |  256f bit  |
| ---------------------- | ---------- | ---------- | ---------- | ---------- | ---------- | ---------- |
|   pubkey size          |       32   |       32   |       48   |       48   |       64   |       64   |
|signature size          |     7856   |    17088   |    16224   |    35664   |    29792   |    49856   |
|   sha2 simple (C)      |    11.5M   |    32.2M   |    17.6M   |    49.4M   |    25.7M   |    49.7M   |
|   sha2 simple (Hybrid) |    11.6M   |    34.5M   |    18.5M   |    49.4M   |    25.7M   |    49.0M   |
|   sha2 simple (Rust)   |    21.9M   |    59.2M   |    31.5M   |    87.1M   |    45.3M   |    92.6M   |
|  shake simple (C)      |    20.5M   |    60.4M   |    31.7M   |    91.9M   |    46.5M   |    91.5M   |
|  shake simple (Hybrid) |    20.8M   |    62.0M   |    31.7M   |    89.9M   |    48.1M   |    92.4M   |
|  shake simple (Rust)   |    37.6M   |   111.6M   |    53.3M   |   156.6M   |    76.5M   |   157.6M   |

In general, the `s` variants take longer to generate a signature, but takes less cycles to verify. The `f` variants are fast in signature generation but takes longer cycles to verify.

### Security Notes
This project has been audited by [ScaleBit](https://scalebit.xyz/reports/20251216-Quantum-Resistant-Lock-Script-Final-Audit-Report.pdf).


## Deployment

### Mainnet

| Parameter   | Value                                                                |
| ----------- | -------------------------------------------------------------------- |
| `code_hash` | `0x302d35982f865ebcbedb9a9360e40530ed32adb8e10b42fbbe70d8312ff7cedf` |
| `hash_type` | `type`                                                               |
| `tx_hash`   | `0x4598d00df2f3dc8bc40eee38689a539c94f6cc3720b7a2a6746736daa60f500a` |
| `index`     | `0x0`                                                                |
| `dep_type`  | `code`                                                               |

### Testnet

| Parameter   | Value                                                                |
| ----------- | -------------------------------------------------------------------- |
| `code_hash` | `0x147ecbb5c5127d982ee1362d2c2bb4267803da2eb006d150e88af6caaa0a7eaf` |
| `hash_type` | `data1`                                                               |
| `tx_hash`   | `0x631d9a6049fb1fc3790e89d9daf35abe535b5e754cd8c3404319319710f0b106` |
| `index`     | `0x0`                                                                |
| `dep_type`  | `code`                                                               |
