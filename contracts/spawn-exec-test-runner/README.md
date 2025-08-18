# spawn-exec-test-runner

An example calling quantum resistant lock via spawn / exec syscall. It serves both as an example, and as a test runner for the quantum resistant lock.

The example script here always assume that the quantum resistant lock resides at cell dep index 1 of current script. However in a more complicated case, a ckb-std [API](https://docs.rs/ckb-std/latest/ckb_std/high_level/fn.look_for_dep_with_hash2.html) is likely to be used to locate the actual cell dep index for the quantum resistant lock.

*This contract was bootstrapped with [ckb-script-templates].*

[ckb-script-templates]: https://github.com/cryptape/ckb-script-templates
