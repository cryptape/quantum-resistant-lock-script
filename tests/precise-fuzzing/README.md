# precise-fuzzing

Quantum resistant lock scripts have 2 different fuzzing setups:

* A normal fuzzing infrastructure is set up in [this folder](../../fuzzing). Where traditional fuzzing techniques are deployed, so sanitizers will aim to detect potential vulnerabilities.
* However, a problem of normal fuzzing workflow, is that we don't know if fuzzing input data will pass validation or not(it's true that a majority of the input corpuses will fail validation, however, the probability is stll not 1, however it is close to 1). In current folder we employ a different fuzzing flow: we take 2 FIPS204 implementation, and we run the same input data to them, asserting that they will both pass the verification, or fail the verification. A fuzzing engine will be leveraged here to find potential cases where one implementation passes but the other one fails.

To differentiate between the 2, we name the new fuzzing workflow, where we introduce 2 implementations and compare their results, as precise-fuzzing. Being precise here means that we do make use of returned verification results of actual code. We are not just running sanitizers here.

## Usage

In this setup we will use Rust to manage dependencies, there is no need to use docker to freeze dependency versions. Nonetheless, there are some initial dependencies:

```
$ rustup install nightly
$ cargo install cargo-fuzz
$ cargo install honggfuzz
$ cargo install cargo-afl
```

Unless otherwise specified, all commands before are expected to run at the root folder of current repository, you can prepare the environment like this:

```
$ git clone https://github.com/xxuejie/quantum-resistant-lock-script
$ cd quantum-resistant-lock-script
$ git checkout overhaul
$ git submodule update --init
```

Similar to lock script based fuzzing, precise fuzzing also supports 3 fuzzing engines:

* libfuzzer powered by [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz)
* honggfuzz powered by [honggfuzz-rs](https://github.com/rust-fuzz/honggfuzz-rs)
* AFL++ powered by [afl.rs](https://github.com/rust-fuzz/afl.rs)

We will explain the usage of them one by one.

### libfuzzer

First, we can generate a set of corpuses to better guide fuzzing engine:

```
$ cargo run --release -p precise-fuzzing --bin corpus-generator -- --output corpus_libfuzzer_1
```

By default, `sha2_128s` parameter set is used, we can also generate corpus for other parameter set:

```
$ cargo run --release -p precise-fuzzing --bin corpus-generator --no-default-features --features sha2_256f -- --output corpus_libfuzzer_2
$ cargo run --release -p precise-fuzzing --bin corpus-generator --no-default-features --features shake_192s -- --output corpus_libfuzzer_3
```

Use the following command to invoke `cargo-fuzz` to run libfuzzer engine:

```
$ cargo +nightly fuzz run --fuzz-dir tests/precise-fuzzing/fuzz fuzz_target_1 corpus_libfuzzer_1
```

Or tweak the command line parameters to fuzz with other parameter sets:

```
$ cargo +nightly fuzz run --fuzz-dir tests/precise-fuzzing/fuzz --no-default-features --features sha2_256f fuzz_target_1 corpus_libfuzzer_2
$ cargo +nightly fuzz run --fuzz-dir tests/precise-fuzzing/fuzz --no-default-features --features shake_192s fuzz_target_1 corpus_libfuzzer_3
```

Due to the nature of fuzzing, it is theoretically possible to use corpus generated for one parameter set against the actual code for another parameter set. However, for the maximum efficiency of fuzzing, we recommend to use the same parameter set in corpus generation and the actual fuzzing flow.

For more details on `cargo-fuzz`(such as tweaking the number of cores to use), please refer to [the fuzz book](https://rust-fuzz.github.io/book/cargo-fuzz.html) or check `cargo +nightly fuzz run --help`.

### honggfuzz

Similar to the above, corpuses can be generated to better guide honggfuzz:

```
$ cargo run --release -p precise-fuzzing --bin corpus-generator -- --output corpus_honggfuzz_1
$ cargo run --release -p precise-fuzzing --bin corpus-generator --no-default-features --features sha2_256f -- --output corpus_honggfuzz_2
$ cargo run --release -p precise-fuzzing --bin corpus-generator --no-default-features --features shake_192s -- --output corpus_honggfuzz_3
```

Now we can fuzz with honggfuzz:

```
$ HFUZZ_INPUT="corpus_honggfuzz_1" \
  HFUZZ_BUILD_ARGS="--package precise-fuzzing" \
  cargo hfuzz run hfuzz-target
```

You can also tweak parameter set to fuzz:

```
$ HFUZZ_INPUT="corpus_honggfuzz_2" \
  HFUZZ_BUILD_ARGS="--package precise-fuzzing --no-default-features --features sha2_256f" \
  cargo hfuzz run hfuzz-target
$ HFUZZ_INPUT="corpus_honggfuzz_3" \
  HFUZZ_BUILD_ARGS="--package precise-fuzzing --no-default-features --features shake_192s" \
  cargo hfuzz run hfuzz-target
```

For more usage on `honggfuzz-rs`, please refer to [its own doc](https://docs.rs/honggfuzz/latest/honggfuzz/), a lot of configurations are passed via environment variables to honggfuzz. You might also find honggfuzz's own [USAGE](https://github.com/google/honggfuzz/blob/master/docs/USAGE.md) page to be quite useful. For example, by combining both docs, we can deduce the command to run honggfuzz with 7 cores:

```
$ HFUZZ_INPUT="corpus_honggfuzz_1" \
  HFUZZ_BUILD_ARGS="--package precise-fuzzing" \
  HFUZZ_RUN_ARGS="--threads 7" \
  cargo hfuzz run hfuzz-target
```

### AFL++

Similar to the above, corpuses can be generated to better guide honggfuzz:

```
$ cargo run --release -p precise-fuzzing --bin corpus-generator -- --output corpus_afl_1
$ cargo run --release -p precise-fuzzing --bin corpus-generator --no-default-features --features sha2_256f -- --output corpus_afl_2
$ cargo run --release -p precise-fuzzing --bin corpus-generator --no-default-features --features shake_192s -- --output corpus_afl_3
```

AFL requires us to build the fuzzing target first:

```
$ cargo afl build -p precise-fuzzing --bin afl-target
```

Now we can fuzz with AFL:

```
$ cargo afl fuzz -i corpus_afl_1 -o corpus_afl_out_1 target/debug/afl-target
```

Unlike the other 2 engines, AFL keeps generated corpus in a separate folder.

It's also possible to fuzz with other parameter sets in AFL, however, we will need to run required build commands first:

```
$ cargo afl build -p precise-fuzzing --bin afl-target --no-default-features --features sha2_256f
$ cargo afl fuzz -i corpus_afl_2 -o corpus_afl_out_2 target/debug/afl-target
```

Or:

```
$ cargo afl build -p precise-fuzzing --bin afl-target --no-default-features --features shake_192s
$ cargo afl fuzz -i corpus_afl_3 -o corpus_afl_out_3 target/debug/afl-target
```

For details on `afl-rs`, please also refer to [the fuzz book](https://rust-fuzz.github.io/book/afl.html), or run `cargo afl fuzz --help`.
