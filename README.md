# quantum-resistant-lock-script
Qantum resistant lock script on CKB, using SPHINCS+


## Performance
Use items for tests/sphincsplus/optimization/run-all-optimization.sh

|               |  128s bit  |  256s bit |
| ------------- | ---------- | --------- |
|   pubkey size |       32   |       64  |
|     sign size |     7888   |    29824  |
|  shake simple |    16.9M   |    37.1M  |
|  shake robust |    34.3M   |    73.2M  |
|   sha2 simple |    10.7M   |    24.7M  |
|   sha2 robust |    22.5M   |    60.4M  |
| haraka simple |    27.5M   |    60.4M  |
| haraka robust |    45.7M   |   102.8M  |
