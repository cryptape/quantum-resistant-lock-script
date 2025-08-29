# Performance

Now that we implement the same script both in C using [sphincsplus](https://github.com/sphincs/sphincsplus) and in Rust using [fips205](https://github.com/integritychain/fips205), it is only natural that one wants to compare their performances.

A proper benchmark with profiling support is certainly more helpful. That being said, a simple trick now, is to rely the validation tests to run both scripts, showing you cycle consumptions of them. For example:

```
$  cargo test --release -p validation-tests _valid_sha2_128f -- --nocapture --test-threads=1
    Finished release profile [optimized + debuginfo] target(s) in 0.11s
     Running unittests src/lib.rs (target/release/deps/validation_tests-692d12450b1718e1)

running 2 tests
test tests::test_c_valid_sha2_128f ... consume cycles: 34501929
consume cycles: 33878883
consume cycles: 33565023
consume cycles: 32470189
consume cycles: 32239676
consume cycles: 34021950
consume cycles: 33558051
consume cycles: 33189664
consume cycles: 32622626
consume cycles: 33640130
consume cycles: 33325347
consume cycles: 32644846
consume cycles: 35040043
consume cycles: 33322009
consume cycles: 33010923
consume cycles: 33497786
consume cycles: 33092091
consume cycles: 32788079
consume cycles: 32628749
consume cycles: 33788600
consume cycles: 32868063
consume cycles: 33720406
consume cycles: 34103378
consume cycles: 32000112
consume cycles: 32949140
consume cycles: 33256957
consume cycles: 32540815
consume cycles: 33254241
consume cycles: 32862637
consume cycles: 33571497
ok
test tests::test_rust_valid_sha2_128f ... consume cycles: 59428241
consume cycles: 57882922
consume cycles: 61812517
consume cycles: 64895707
consume cycles: 59569192
consume cycles: 59281456
consume cycles: 59584968
consume cycles: 58867551
consume cycles: 58044778
consume cycles: 58315083
consume cycles: 62239870
consume cycles: 59425142
consume cycles: 58869883
consume cycles: 60830815
consume cycles: 58028911
consume cycles: 59849026
consume cycles: 61669747
consume cycles: 60273120
consume cycles: 63498549
consume cycles: 57318310
consume cycles: 62086683
consume cycles: 59580866
consume cycles: 62928518
consume cycles: 58309036
consume cycles: 62943155
consume cycles: 63507692
consume cycles: 62660955
consume cycles: 60973761
consume cycles: 61812204
consume cycles: 57748085
ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 22 filtered out; finished in 8.89s
```

This is certainly not a good benchmark, a new signature will be randomly generated for each iteration. However, it provides us with a general trend here: one can estimate the average cycle consumptions of each script.

The command can also be tweaked to run signatures using different parameter set:

* `cargo test --release -p validation-tests _valid_sha2_128f -- --nocapture --test-threads=1`
* `cargo test --release -p validation-tests _valid_sha2_128s -- --nocapture --test-threads=1`
* `cargo test --release -p validation-tests _valid_sha2_192f -- --nocapture --test-threads=1`
* `cargo test --release -p validation-tests _valid_sha2_192s -- --nocapture --test-threads=1`
* `cargo test --release -p validation-tests _valid_sha2_256f -- --nocapture --test-threads=1`
* `cargo test --release -p validation-tests _valid_sha2_256s -- --nocapture --test-threads=1`
* `cargo test --release -p validation-tests _valid_shake_128f -- --nocapture --test-threads=1`
* `cargo test --release -p validation-tests _valid_shake_128s -- --nocapture --test-threads=1`
* `cargo test --release -p validation-tests _valid_shake_192f -- --nocapture --test-threads=1`
* `cargo test --release -p validation-tests _valid_shake_192s -- --nocapture --test-threads=1`
* `cargo test --release -p validation-tests _valid_shake_256f -- --nocapture --test-threads=1`
* `cargo test --release -p validation-tests _valid_shake_256s -- --nocapture --test-threads=1`
