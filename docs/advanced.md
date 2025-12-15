# Overview

`c-sphincs-all-in-one-lock` is a CKB lock script using [NIST-approved](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf) [SPHINCS+](https://github.com/sphincs/sphincsplus) algorithm for signature verification. Once deployed, it provides a unique beauty: the whole of CKB can function with only 3 cryptographic hash functions: eaglesong for POW, blake2b for data structure hashing, and shake/sha2 used in SPHINCS+.

While the [simple introduction](./simple.md) hides enough fact so one can treat this lock as a simple lock supporting one public key with one signature. `c-sphincs-all-in-one-lock` is in fact designed as a multisig lock, supporting for example 2-of-3, 3-of-5, 7-or-11 or other multisig configurations. In this post, we will explain in more details how one can configure `c-sphincs-all-in-one-lock` for different scenarios.

# Script Args

The `args` field in a CKB lock script using `c-sphincs-all-in-one-lock` contains a 32-byte hash value of a structure named `multisig configuration`. Precisely, given a `multisig configuration`(for now think of it as a series of bytes, we will explain this structure in more details below), a [blake2b](https://www.blake2.net/) hash function of 32-byte output length, using `ckb-sphincs+-sct` as the personalization field, hashes the `multisig configuration` into 32-byte hash data. This 32-byte data is then put into `args` field to denote identity.

## Multisig Configuration

The `multisig configuration` used by `c-sphincs-all-in-one-lock` is highly inspired by the [secp256k1 multisig lock](https://github.com/nervosnetwork/ckb-system-scripts/blob/934166406fafb33e299f5688a904cadb99b7d518/c/secp256k1_blake160_multisig_all.c#L8-L34) deployed in CKB's genesis block. However, the value of the original reserved field is changed, as well as the placements of public keys and signatures.

A multisig configuration uses the following structure:

```
<S(1 byte)> <R(1 byte)> <M<(1 byte)> <N(1 byte)> <param flag 1> <public key 1> <param flag 2> <public key 2> ...
```

Each field here serves a different purpose:

* `S`: `S` represents a reserved field. It must be of value `0x80`, the value is intentially chosen to be different from the secp256k1 multisig lock deployed in CKB's genesis block.
* `R`: `R` represents how many starting public keys are required. For example, in a 3-of-5 setup, one might want to say that signatures for public key A and B must always be present so as to unlock the cell. In this case one can put public key A and B at the start of the public key list, and then set `R` to 2.
* `M`: `M` represents the threshold, meaning how many signatures must be provided to unlock the cell. For instance, in a 3-of-5 setup, `M` must be 3.
* `N`: `N` represents the avialble public keys, in a 3-of-5 setup, `N` must be 5.

If any signature fails verification, the entire process fails, even when the remaining signatures (more than `M`) are valid. 
In the UTXO model, transactions can be validated off-chain by SDKs or tools, allowing invalid signatures to be removed before broadcasting to the P2P network. Therefore, the design enforces a strict limit: provide exactly $M$ signatures (no more, no less).

`N` also denotes how many pairs of `param flag` and `public key` will follow. Each `param id` will be 1 byte, the higher 7 bit represents `param ID`, denoting the parameter set to use, the lowest bit is a signature flag, for multisig configuration, this bit is always 0. A public key can range from 48 to 64 depending on the parameter set. The exact of value in `param id` indicates the length of public key followed.

## Multisig ID, Param ID

`Param ID` determines the SPHINCS+ parameter set to be used for a public key. There are 12 possible values:

* 48: sphincs-sha2-128f
* 49: sphincs-sha2-128s
* 50: sphincs-sha2-192f
* 51: sphincs-sha2-192s
* 52: sphincs-sha2-256f
* 53: sphincs-sha2-256s
* 54: sphincs-shake-128f
* 55: sphincs-shake-128s
* 56: sphincs-shake-192f
* 57: sphincs-shake-192s
* 58: sphincs-shake-256f
* 59: sphincs-shake-256s

This [file](../crates/ckb-fips205-utils/src/lib.rs) contains the canonical source of param ID definitions. All other sources rely on this single file, so if you have any doubt, always check this file.

Each public key must be associated with one param ID, otherwise we will not know what parameter to use for the public key, nor do we even know the length of a public key.

## Explanation of Secret Prefixes in Simple Introduction

Now we can explain the secret prefixes included in [simple introduction](./simple.md). Take `sphincs-sha2-256s` for example, the prefix used in script args is:

```
80 01 01 01 6a
```

Let's break them one byte at once:

1. `S`, or reserved field is always `0x80`.
2. `R` is `0x01`, which is simply 1, this means the first public key must have a corresponding signature available.
3. `M` is `0x01`, which is simply 1, this means one signature must be available to unlock the cell.
4. `N` is `0x01`, which is simply 1, this means one public key is available. In other words, this is a 1-of-1 configuration, also requiring the signature for first public key must be available(actually this is redundant requirement for a 1-of-1 configuration).
5. Finally, the lowest 1 bit of `0x6a` is 0, meaning a signature is missing, the higher 7 bit is `0x35` or 53, which is the param ID for `sphincs-sha2-256s`.

Now it's clear that the 5-byte prefix is merely 4 bytes of multisig configuration header for 1-of-1 configuration, and another byte for the param ID and signature flag. This concludes that the single-signature case, is simply a special case of the multi-signature configuration.

# Witness

Following conventions set up by CKB lock scripts deployed in the genesis block, `c-sphincs-all-in-one-lock` assumes that the first witness in its own script group(i.e., one can locate the first input cell using current lock script, then find the witness of the same index as this particular input cell), contains a [WitnessArgs](https://docs.rs/ckb-gen-types/latest/ckb_gen_types/packed/struct.WitnessArgs.html) structure in the molecule serialization format. It then extracts values stored in the `lock` field of the `WitnessArgs` structure, and use those values for transaction validation and signature verifications.

The values in the `lock` field of the `WitnessArgs` structure, are of the following format:

```
<S(1 byte)> <R(1 byte)> <M<(1 byte)> <N(1 byte)> <PWOS 1> <PWOS 2> ...
```

Please refer to `Script Args` section for the explanation of `S`, `R`, `M`, `N`, they are of the exact same value.

`PWOS` stands for `Public key With Optional Signature`. In a multisig configuration, there might be N public keys, and any combination M of those N(of course this is an oversimplification, `R` would forbade certain combinations, let's ignore this fact for a moment) public keys, could have a signature attached. `PWOS` is designed to cope with this problem: either a single param ID with public key(meaning no signature is gathered from this public key), or a param ID, a public key and a signature are concatenated together(meaning a signature is generated from this public key).

As a result, a `PWOS` can be either one of the following 2 structures:

```
<param flag> <public key> <signature>
```

or:

```
<param flag> <public key>
```

`param flag` is defined similarly to the one in `multisig configuration`: the higher 7-bit represent `param ID`, while the lowest bit is a signature flag, meaning if a signature is present for current public key.

There must be the same number of `PWOS` objects here as the value stored in `N`. Of the `N` `PWOS` objects, there must be exactly `M` of them with signatures present. And the first `R` `PWOS` objects, must all have signatures.

`PWOS` objects must be sorted by public keys, in the same order of public keys as the `multisig configuration` defined in `Script Args` section. This is a key difference compared to multisig design in lock script from the genesis block.

While it is not a direct match, it is possible to derive `multisig configuration` from the data included in `lock` field of the `WitnessArgs` structure:

* Take the first 4 bytes of values for `S`, `R`, `M`, `N`
* For each `PWOS`, clear the highest `param flag` to take the `param ID`, and then take the public key included in this `PWOS`

Assuming data atored in witness are valid, `c-sphincs-all-in-one-lock` verifies that each included signature using the provided public key, against a signing message defined in the next section. The lock script completes with a success return code if the verification succeeds, otherwise an error code would be generated, denoting a failure.

## Signing Message

While SPHINCS+ itself supports variable length of signing messages, `c-sphincs-all-in-one-lock` requires that the signing message used here to be 32 bytes long. It is actually calculated using [CKB_TX_MESSAGE_ALL](https://github.com/nervosnetwork/rfcs/pull/446) specification. In `CKB_TX_MESSAGE_ALL` process, a blake2b hash function of 32-byte output length, using `ckb-sphincs+-msg` as the personalization field is leveraged as the hasher. The resulting 32-byte hash will then be used as the signing message.
