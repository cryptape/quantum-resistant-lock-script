# Overview

`c-sphincs-all-in-one-lock` is a CKB lock script using [NIST-approved](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf) [SPHINCS+](https://github.com/sphincs/sphincsplus) algorithm for signature verification. Once deployed, it provides a unique beauty: the whole of CKB can function with only 3 cryptographic hash functions: eaglesong for POW, blake2b for data structure hashing, and shake/sha2 used in SPHINCS+.

While the [simple introduction](./simple.md) hides enough fact so one can treat this lock as a simple lock supporting one public key with one signature. `c-sphincs-all-in-one-lock` is in fact designed as a multisig lock, supporting for example 2-of-3, 3-of-5, 7-or-11 or other multisig configurations. In this post, we will explain in more details how one can configure `c-sphincs-all-in-one-lock` for different scenarios.

# Script Args

The `args` field in a CKB lock script using `c-sphincs-all-in-one-lock` contains a 32-byte hash value of a structure named `multisig configuration`. Precisely, given a `multisig configuration`(for now think of it as a series of bytes, we will explain this structure in more details below), a [blake2b](https://www.blake2.net/) hash function of 32-byte output length, using `ckb-sphincs+-sct` as the personalization field, hashes the `multisig configuration` into 32-byte hash data. This 32-byte data is then put into `args` field to denote identity.

## Multisig Configuration

The `multisig configuration` used by `c-sphincs-all-in-one-lock` is highly inspired by the [secp256k1 multisig lock](https://github.com/nervosnetwork/ckb-system-scripts/blob/934166406fafb33e299f5688a904cadb99b7d518/c/secp256k1_blake160_multisig_all.c#L8-L34) deployed in CKB's genesis block. However, the value of the original reserved field is changed, as well as the placements of public keys and signatures.

A multisig configuration uses the following structure:

```
<I(1 byte)> <R(1 byte)> <M<(1 byte)> <N(1 byte)> <param id 1> <public key 1> <param id 2> <public key 2> ...
```

Each field here serves a different purpose:

* `I`: `I` represents multisig ID, `c-sphincs-all-in-one-lock` expands the reserved field in the original multisig structure. To denote the differences, the higher 4 bits of `I` will always be set to `0b1000`. The lower 4 bits of `I` store `param ID`, we will explain this field in more detail in the next section.
* `R`: `R` represents how many starting public keys are required. For example, in a 3-of-5 setup, one might want to say that signatures for public key A and B must always be present so as to unlock the cell. In this case one can put ublic key A and B at the start of the public key list, and then set `R` to 2.
* `M`: `M` represents the threshold, meaning how many signatures must be provided to unlock the cell. For instance, in a 3-of-5 setup, `M` must be 3.
* `N`: `N` represents the avialble public keys, in a 3-of-5 setup, `N` must be 5.

`N` also denotes how many pairs of `param id` and `public key` will follow. Each `param id` will be 1 byte, the higher 4 bit of each `param id` here will always be zero. A public key can range from 48 to 64 depending on the parameter set. However, the preceding `param id` already determines the length of a public key.

## Multisig ID, Param ID

`Param ID` determines the SPHINCS+ parameter set to be used for a public key. There are 12 possible values:

* 1: sphincs-sha2-128f
* 2: sphincs-sha2-128s
* 3: sphincs-sha2-192f
* 4: sphincs-sha2-192s
* 5: sphincs-sha2-256f
* 6: sphincs-sha2-256s
* 7: sphincs-shake-128f
* 8: sphincs-shake-128s
* 9: sphincs-shake-192f
* 10: sphincs-shake-192s
* 11: sphincs-shake-256f
* 12: sphincs-shake-256s

This [file](../params.txt) contains the canonical source of param ID definitions. The source code also relies on this file in the compilation process, so if you have any doubt, always check this file.

It's obvious that each public key must be associated with one param ID, otherwise we will not know what parameter to use for the public key, nor do we even know the length of a public key. However, one might notice that multisig ID also contains a param ID, and wonder what this is used for. The param ID here, actually is used to denote different invocation modes of `c-sphincs-all-in-one-lock`.

## Invocation Mode

Due to unique designs in `c-sphincs-all-in-one-lock`(please refer to [internals](./internals.md) for more information), 2 different invocation modes exist. One leverages [exec](https://github.com/nervosnetwork/rfcs/blob/bd5d3ff73969bdd2571f804260a538781b45e996/rfcs/0034-vm-syscalls-2/0034-vm-syscalls-2.md#exec) syscall, while the other leverages [spawn](https://github.com/nervosnetwork/rfcs/blob/bd5d3ff73969bdd2571f804260a538781b45e996/rfcs/0050-vm-syscalls-3/0050-vm-syscalls-3.md#spawn) syscalls. When `c-sphincs-all-in-one-lock` starts execution, a `root script` first begins execution, it might invoke `leaf scripts` to do actual SPHINCS+ verification(but as the internals doc explains, both `root script` and `leaf scripts`, actually live within a single `c-sphincs-all-in-one-lock`).

The param ID included in multisig ID field, is used to control different invocation modes:

* When a multisig ID contains one of the 12 valid param ID, the root script, when finishes all transaction level validations, will fire up an `exec` syscall based on the param ID included in the multisig ID. The specified leaf script by the param ID will replace root script, and validates all signatures in the designated witness field of current transaction. Note that this invocation mode is limited to the case where either a single public key is used(single-sign mode), or multiple public keys using the same parameter set are used. When this requirement is satisfied, current invocation mode provides lower cycle consumptions.
* When the lower 4 bits of multisig ID are set to zero, the root script will then utilize `spawn` syscall to create up to 12 child VM instances, each using a different parameter set, the root script then loop through each different signature to verify, send the signature together with the public key to the VM instance of desginated parameter set to validate. This invocation mode has the flexibility that each different public key in the multiple-signature configuration can use different parameter set. However as `spawn` and data exchanges between VMs are involved, this will definitly require more cycle usage compared to the above mode.

## Explanation of Secret Prefixes in Simple Introduction

Now we can explain the secret prefixes included in [simple introduction](./simple.md). Take `sphincs-sha2-256s` for example, the prefix used in script args is:

```
86 01 01 01 06
```

Let's break them one byte at once:

1. `I`, or the multisig ID is `0x86`, which is in fact `0b10000110`. The higher 4 bits `0b1000` is required by multisig configuration definition. The lower 4 bites `0b0110` is in fact 6, the parameter ID for `sphincs-sha2-256s`.
2. `R` is `0x01`, which is simply 1, this means the first public key must have a corresponding signature available.
3. `M` is `0x01`, which is simply 1, this means one signature must be available to unlock the cell.
4. `N` is `0x01`, which is simply 1, this means one public key is available. In other words, this is a 1-of-1 configuration, also requiring the signature for first public key must be available(actually this is redundant requirement for a 1-of-1 configuration).
5. Finally, `0x06` is in fact the param ID for the first public key, which is `sphincs-sha2-256s`.

Now it's clear that the 5-byte prefix is merely 4 bytes of multisig configuration header for 1-of-1 configuration, and another byte for the param ID. This concludes that the single-signature case, is simply a special case of the multi-signature configuration.

# Witness


Following conventions set up by CKB lock scripts deployed in the genesis block, `c-sphincs-all-in-one-lock` assumes that the first witness in its own script group(i.e., one can locate the first input cell using current lock script, then find the witness of the same index as this particular input cell), contains a [WitnessArgs](https://docs.rs/ckb-gen-types/latest/ckb_gen_types/packed/struct.WitnessArgs.html) structure in the molecule serialization format. It then extracts values stored in the `lock` field of the `WitnessArgs` structure, and use those values for transaction validation and signature verifications.

The values in the `lock` field of the `WitnessArgs` structure, are of the following format:

```
<I(1 byte)> <R(1 byte)> <M<(1 byte)> <N(1 byte)> <PWOS 1> <PWOS 2> ...
```

Please refer to `Script Args` section for the explanation of `I`, `R`, `M`, `N`, they are of the exact same value.

`PWOS` stands for `Public key With Optional Signature`, there must be the same number of `PWOS` objects here as the value stored in `N`. A `PWOS` can be either one of the following 2 structures:

```
<param flag with signature bit set> <public key> <signature>
```

or:

```
<param flag without signature bit set> <public key>
```

Notice here `param flag` precedes public key, which is slightly different than `multisig configuration` defined in `Script Args` section. The lower 4-bit of `param flag` contains `param ID`, the higher 4-bit of `param flag` is either `0b1000`, meaning a signature is present, or `0b0000`, meaning no signature is available for current public key.

Of the `N` `PWOS` objects, there must be exactly `M` of them with signatures present. And the first `R` `PWOS` objects, must all have signatures.

`PWOS` objects must be sorted by public keys, in the same order of public keys as the `multisig configuration` defined in `Script Args` section. This is a key difference compared to multisig design in lock script from the genesis block.

While it is not a direct match, it is possible to derive `multisig configuration` from the data included in `lock` field of the `WitnessArgs` structure:

* Take the first 4 bytes of values for `I`, `R`, `M`, `N`
* For each `PWOS`, clear the upper 4 bits `param flag` to take the `param ID`, also take each public key

With a valid data in witness, `c-sphincs-all-in-one-lock` verifies that each included signature using the provided public key, against a signing message defined in the next section. The lock script completes with a success return code if the verification succeeds, otherwise an error code would be generated, denoting a failure.

## Signing Message

While SPHINCS+ itself supports variable length of signing messages, `c-sphincs-all-in-one-lock` requires that the signing message used here to be 32 bytes long. It is actually calculated using [CKB_TX_MESSAGE_ALL](https://github.com/nervosnetwork/rfcs/pull/446) specification. In `CKB_TX_MESSAGE_ALL` process, a blake2b hash function of 32-byte output length, using `ckb-sphincs+-msg` as the personalization field is leveraged as the hasher. The resulting 32-byte hash will then be used as the signing message.
