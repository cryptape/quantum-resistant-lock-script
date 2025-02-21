# Overview

This document explains important points of `c-sphincs-all-in-one-lock` internals.

## Umbrella of Scripts

The reference implementation of [SPHINCS+](https://github.com/sphincs/sphincsplus) has one quirk: it sets the parameter set of SPHINCS+ at build time, not at runtime. This means when we compile a binary using the reference implementation, only one parameter set will be available to use.

To cope with this issue, we employ a different solution: `c-sphincs-all-in-one-lock` is not simply one CKB script underneath, it is the combination of 13 CKB scripts together:

* For each parameter set of SPHINCS+, a CKB script(named `leaf script`) is built to do the SPHINCS+ verification work alone.
* An entry CKB script(named `root script`) is also built.

`c-sphincs-all-in-one-lock` is actually the concatenation of the root script and the 12 leaf scripts together. When CKB-VM loads `c-sphincs-all-in-one-lock`, only the root script will be loaded and executed. Depending on invocation mode and parameter set configurations, the root script will first do the transaction level validations, such as calculating signing message, doing preliminary checks on `multisig configuration`, etc, then locate one or more leaf scripts, and invokes the leaf script(s) via [exec](https://github.com/nervosnetwork/rfcs/blob/bd5d3ff73969bdd2571f804260a538781b45e996/rfcs/0034-vm-syscalls-2/0034-vm-syscalls-2.md#exec) or [spawn](https://github.com/nervosnetwork/rfcs/blob/bd5d3ff73969bdd2571f804260a538781b45e996/rfcs/0050-vm-syscalls-3/0050-vm-syscalls-3.md#spawn) syscalls. The left scripts then complete the actual SPHINCS+ signature verification work. This way with one `umbrella` of scripts, we manage to provide support for all parameter sets.

Due to this particular design, special tools are required to patch and merge binaries, we have hand-written [tools](../build-tools) to fulfill those purposes:

* [build-params-finder](../build-tools/build-params-finder): starting from [parameter set definition file](../params.txt), this tool builds a C header file containing injection points for `offsets` for each leaf script in the umbrella script, and handy utility structures for the root script.
* [patch-root-binary](../build-tools/patch-root-binary): when root script(however the offsets are invalid at this point) and leaf scripts are built, this tool reads the sizes for each script, calculates the correct offsets for all leaf scripts, patch the root binary with the correct offsets, and then merge all scripts into a single umbrella script.

We do hope this `umbrella` design can help inspire more different kinds of CKB scripts in the future.
