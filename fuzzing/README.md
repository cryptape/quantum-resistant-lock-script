# fuzzing

This is the fuzzing setup for quantum resistant lock script.

It uses 2 spectrums: on the one hand, 13 scripts(12 leaf scripts + root script) need fuzzing, on the other hand, 3 fuzzing engines are provided. So a total of 39 fuzzers will be generated.

## Usage

```bash
$ make build
$ make -C fuzzing repl
```

Or if you need proxy setup:

```bash
$ make build
$ make -C fuzzing repl DOCKER_RUN_ARGS="-e ALL_PROXY=$ALL_PROXY -e HTTP_PROXY=$HTTP_PROXY -e HTTPS_PROXY=$HTTPS_PROXY"
```

In the docker process, build and generate everything:

```bash
(docker) # make -C fuzzing
```

You can regenerate corpuses alone:

```bash
(docker) # make -C fuzzing prepare
```

When fully generated, `fuzzing/corpus` will contain corpuses for all 13 different scripts, you can now mix script to fuzz with fuzzing engines:

```bash
(docker) # cp -r fuzzing/corpus/root fuzzing/corpus_root_llvm
(docker) # ./fuzzing/root_llvm_fuzzer fuzzing/corpus_root_llvm

(docker) # cp -r fuzzing/corpus/sphincs-sha2-192f fuzzing/corpus_llvm_sha_192f
(docker) # ./fuzzing/sphincs-sha2-192f_llvm_fuzzer fuzzing/corpus_llvm_sha_192f -jobs=4

(docker) # cp -r fuzzing/corpus/sphincs-shake-256f fuzzing/corpus_hong_shake_256f
(docker) # honggfuzz -i fuzzing/corpus_hong_shake_256f -- fuzzing/sphincs-shake-256f_honggfuzz_fuzzer ___FILE___

(docker) # cp -r fuzzing/corpus/root fuzzing/corpus_afl_root
(docker) # afl-fuzz -i fuzzing/corpus_afl_root -o fuzzing/corpus_afl_root_out -- fuzzing/root_aflxx_fuzzer @@
```
