# Overview

`c-sphincs-all-in-one-lock` is a CKB lock script using [NIST-approved](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf) [SPHINCS+](https://github.com/sphincs/sphincsplus) algorithm for signature verification. Once deployed, it provides a unique beauty: the whole of CKB can function with only 3 cryptographic hash functions: eaglesong for POW, blake2b for data structure hashing, and shake/sha2 used in SPHINCS+.

Our SPHINCS+ lock supports all 12 parameter sets approved by NIST in a single lock(where the `all-in-one` part in the name comes from). A user can decide to use any of the provided parameter sets to guard their cells. To use a CKB lock script, there are several parts to know:

* What data shall be put into lock script's `args` field?
* What data shall be put into witness to unlock a cell using this lock script?
* Since SPHINCS+ lock uses a signature verification process, how the signing message shall be calculated?

We will explain them one by one.

# Script Args

Once a wallet utilizing SPHINCS+ has been created, a pair of public and private(secret) keys will be generated. While the private(secret) key must stay private, the public key will be transformed and included in `args` field of a lock script to denote identity. While multiple users of the SPHINCS+ lock script all use the same `code_hash` and `hash_type`, each of them use a different value in `args` field to distinguish cells from different users.

For different parameter sets, a different set of 5-byte prefix will be used(listed below in hexadecimal form):

1. sphincs-sha2-128f: `80 01 01 01 60`
2. sphincs-sha2-128s: `80 01 01 01 62`
3. sphincs-sha2-192f: `80 01 01 01 64`
4. sphincs-sha2-192s: `80 01 01 01 66`
5. sphincs-sha2-256f: `80 01 01 01 68`
6. sphincs-sha2-256s: `80 01 01 01 6a`
7. sphincs-shake-128f: `80 01 01 01 6c`
8. sphincs-shake-128s: `80 01 01 01 6e`
9. sphincs-shake-192f: `80 01 01 01 70`
10. sphincs-shake-192s: `80 01 01 01 72`
11. sphincs-shake-256f: `80 01 01 01 74`
12. sphincs-shake-256s: `80 01 01 01 76`

The defined prefix is then concatenated with the public key(could be 32, 48 or 64 bytes) to form a series of bytes:

```
<prefix for a parameter set used to generate the public key> <public key>
```

We then run a [blake2b](https://www.blake2.net/) hash function of 32-byte output length, using `ckb-sphincs+-sct` as the personalization field. This 32-byte hash generated from the blake2b function, shall then be put into `args` field to denote identity.

# Witness Placement

Following conventions set up by CKB lock scripts deployed in the genesis block, `c-sphincs-all-in-one-lock` assumes that the first witness in its own script group(i.e., one can locate the first input cell using current lock script, then find the witness of the same index as this particular input cell), contains a [WitnessArgs](https://docs.rs/ckb-gen-types/latest/ckb_gen_types/packed/struct.WitnessArgs.html) structure in the molecule serialization format. It then extracts values stored in the `lock` field of the `WitnessArgs` structure, and use those values for transaction validation and signature verifications.

The values in the `lock` field of the `WitnessArgs` structure, are of the following format:

```
<witness prefix for a parameter set used to generate the public key> <public key> <signature>
```

The prefixes used here are also 5 bytes in length, but slightly different compared to prefixes used to calculate script args:

1. sphincs-sha2-128f: `80 01 01 01 61`
2. sphincs-sha2-128s: `80 01 01 01 63`
3. sphincs-sha2-192f: `80 01 01 01 65`
4. sphincs-sha2-192s: `80 01 01 01 67`
5. sphincs-sha2-256f: `80 01 01 01 69`
6. sphincs-sha2-256s: `80 01 01 01 6b`
7. sphincs-shake-128f: `80 01 01 01 6d`
8. sphincs-shake-128s: `80 01 01 01 6f`
9. sphincs-shake-192f: `80 01 01 01 71`
10. sphincs-shake-192s: `80 01 01 01 73`
11. sphincs-shake-256f: `80 01 01 01 75`
12. sphincs-shake-256s: `80 01 01 01 77`

`c-sphincs-all-in-one-lock` validates that the values in the `lock` field of the `WitnessArgs` structure follow the above defined format. It then configures SPHINCS+ using the given parameter set, verifies the signature using the provided public key, against a signing message defined in the next section. The lock script completes with a success return code if the verification succeeds, otherwise an error code would be generated, denoting a failure.

## Signing Message

While SPHINCS+ itself supports variable length of signing messages, `c-sphincs-all-in-one-lock` requires that the signing message used here to be 32 bytes long. It is actually calculated using [CKB_TX_MESSAGE_ALL](https://github.com/nervosnetwork/rfcs/pull/446) specification. In `CKB_TX_MESSAGE_ALL` process, a blake2b hash function of 32-byte output length, using `ckb-sphincs+-msg` as the personalization field is leveraged as the hasher. The resulting 32-byte hash will then be used as the signing message.

# A prefix of 5 bytes is too long!

It is only natural that one doubts the necessity of a 5-byte prefix. `c-sphincs-all-in-one-lock` only has 12 different parameter sets, a mere byte is enough as the prefix! We come up with this design for the following reasons:

* In this simple introduction, we have been hidding the fact that `c-sphincs-all-in-one-lock` actually supports multi-signature. This means that one can use `c-sphincs-all-in-one-lock` as a multisig lock, doing for example 2-of-3, 3-of-5, 7-or-11 or other multisig configurations. The way we use `c-sphincs-all-in-one-lock` here with only one public key and one signature, is just a special case of the multisig lock underneath.
* SPHINCS+, in its current version, has a slight drawback: the signature size is rather big. Depending on the parameter set used, a SPHINCS+ signature ranges from 7856 bytes to 49856 bytes. The only place where a prefix will be included on chain, will be in the witness field together with the signature, since the signature is already ~8 - 50KB, a 5-byte prefix is not really our concern.

Please refer to the [advanced introduction](./advanced.md) if you want to learn more about the multisig process.
