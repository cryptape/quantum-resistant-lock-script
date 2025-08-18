# Overview

This document explains important points of `c-sphincs-all-in-one-lock` internals.

## Combination of different specs

Note that the `c-sphincs-all-in-one-lock`, or in fact this repository, combines 3 different piece to build a CKB lock script:

* Quantum resistant signature algorithm powered by [SPHINCS+](https://github.com/sphincs/sphincsplus).
* The new `CKB_TX_MESSAGE_ALL` message signing algorithm described in [this RFC](https://github.com/nervosnetwork/rfcs/pull/446).
* A new multisig format described in [this RFC](https://github.com/nervosnetwork/rfcs/pull/448).

So if you are puzzled by one particular point in the implementation, chances are one of the RFCs could give you a little hint.

## Umbrella of Scripts

The reference implementation of [SPHINCS+](https://github.com/sphincs/sphincsplus) has one quirk: it sets the parameter set of SPHINCS+ at build time, not at runtime. This means when we compile a binary using the reference implementation, only one parameter set will be available to use.

To cope with this issue, we employ a different solution: `c-sphincs-all-in-one-lock` is not simply one CKB script underneath, it is the combination of 13 CKB scripts together:

* For each parameter set of SPHINCS+, a CKB script(named `leaf script`) is built to do the SPHINCS+ verification work alone.
* An entry CKB script(named `root script`) is also built.

`c-sphincs-all-in-one-lock` is actually the concatenation of the root script and the 12 leaf scripts together. When CKB-VM loads `c-sphincs-all-in-one-lock`, only the root script will be loaded and executed. Depending on invocation mode(mentioned below) and parameter set configurations, the root script will first do the transaction level validations, such as calculating signing message, doing preliminary checks on `multisig configuration`, etc, then locate one or more leaf scripts, and invokes the leaf script(s) via [exec](https://github.com/nervosnetwork/rfcs/blob/bd5d3ff73969bdd2571f804260a538781b45e996/rfcs/0034-vm-syscalls-2/0034-vm-syscalls-2.md#exec) or [spawn](https://github.com/nervosnetwork/rfcs/blob/bd5d3ff73969bdd2571f804260a538781b45e996/rfcs/0050-vm-syscalls-3/0050-vm-syscalls-3.md#spawn) syscalls. The left scripts then complete the actual SPHINCS+ signature verification work. This way with one `umbrella` of scripts, we manage to provide support for all parameter sets.

Due to this particular design, special tools are required to patch and merge binaries, we have hand-written [tools](../build-tools) to fulfill those purposes:

* [build-params-finder](../build-tools/build-params-finder): starting from [parameter set definition file](../params.txt), this tool builds a C header file containing handy utility structures for fetching different parameter sets (with leaf script offsets) from root script.
* [script-merge-tool](../build-tools/script-merge-tool): this is a generic tool that helps build offset symbol definition sources from built leaf scripts, and also patch root script to update correct offsets from leaf scripts. This tool is designed so no logic of our SPHINCS+ lock is required. Ideally it can be reused elsewhere for similar purposes

We do hope this `umbrella` design can help inspire more different kinds of CKB scripts in the future.

### Callee of Spawn or Exec

There is one side effect of the `umbrella` design: when you use spawn or exec syscalls to call the `c-sphincs-all-in-one-lock` as a callee, you must provide the cell dep index of the `c-sphincs-all-in-one-lock` script in current transaction in `argv[0]` of spawn or exec's arguments. The cell dep index must first be put in 64-bit little endian format, then be encoded via `zero escaping`. See [spawn-exec-test-runner](../contracts/spawn-exec-test-runner) as an example that calls `c-sphincs-all-in-one-lock` as a callee script.

## Invocation Mode

Due to the above mentioned design in the C script, 2 different invocation modes exist. One leverages [exec](https://github.com/nervosnetwork/rfcs/blob/bd5d3ff73969bdd2571f804260a538781b45e996/rfcs/0034-vm-syscalls-2/0034-vm-syscalls-2.md#exec) syscall, while the other leverages [spawn](https://github.com/nervosnetwork/rfcs/blob/bd5d3ff73969bdd2571f804260a538781b45e996/rfcs/0050-vm-syscalls-3/0050-vm-syscalls-3.md#spawn) syscalls. The actual invocation mode to use depends on param IDs included in the multisig configuration:

* When all public keys in the multisig configuration use the same param ID(the same parameter set), the root script, when finishes all transaction level validations, will fire up a single `exec` syscall, replacing it with a leaf script for verifying the single parameter set used by all the public keys. The leaf script will then perform verification work for all signatures.
* When more than one param ID(parameter set) is used, the root script when then utilize `spawn` syscalls to create up to 12 child VM instances, each with a different parameter set. In this case, the root script loops through each signature, send it to a desginated child VM to do the actual VM verification work.

While a single `exec` syscall reduces resource consumption, `spawn` provides more flexibility, since multiple parameter sets can be used in a single multisig configuration.
