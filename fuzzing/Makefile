cur_dir = $(dir $(abspath $(firstword $(MAKEFILE_LIST))))
TOP := $(cur_dir)/..

THASH = simple
C_SCRIPT_NAME := c-sphincs-all-in-one-lock
LOCK_DIR := $(TOP)/contracts/$(C_SCRIPT_NAME)
SPHINCS_PLUS_DIR := $(TOP)/deps/sphincsplus/ref
include $(TOP)/mk/files.mk

CLANG := $(shell $(TOP)/scripts/find_clang)
CLANGXX := $(subst clang,clang++,$(CLANG))

HFUZZ_CLANG := hfuzz-clang
HFUZZ_CLANGXX := hfuzz-clang++

AFLXX_CLANG := afl-clang-fast
AFLXX_CLANGXX := afl-clang-fast++

LLVM_FUZZER_SETTINGS := -fsanitize=fuzzer,address,undefined -fno-sanitize=alignment
HONGGFUZZ_SETTINGS := -fsanitize=address,undefined -fno-sanitize=alignment
AFLXX_SETTINGS := -fsanitize=address,undefined -fno-sanitize=alignment

COMMON_CFLAGS := -Wall -Werror -Wno-unused-function \
	-g -O3 -DFUZZING -I $(cur_dir)

USE_TEXT_PROTO :=
ifeq (true,$(USE_TEXT_PROTO))
	COMMON_CFLAGS += -DCKB_FUZZING_USE_TEXT_PROTO
endif

SCRIPT_CFLAGS := $(COMMON_CFLAGS) \
	-DCKB_DECLARATION_ONLY -DCKB_VM \
	-I $(TOP)/deps/ckb-c-stdlib -I $(TOP)/deps/ckb-c-stdlib/libc \
	-I $(LOCK_DIR) -I $(LOCK_DIR)/utils -I $(LOCK_DIR)/build \
	-I $(SPHINCS_PLUS_DIR)
LLVM_FUZZER_CFLAGS := $(COMMON_CFLAGS) \
	$(shell pkg-config --silence-errors --cflags libprotobuf-mutator) \
	-DCKB_FUZZING_DEFINE_LLVM_FUZZER_INTERFACE
HONGGFUZZ_CFLAGS := $(COMMON_CFLAGS) \
	-DCKB_FUZZING_DEFINE_FILENAME_INTERFACE
AFLXX_CFLAGS := $(COMMON_CFLAGS) \
	-DCKB_FUZZING_DEFINE_AFLXX_INTERFACE

LDFLAGS := -lprotobuf
LLVM_FUZZER_LDFLAGS := $(LDFLAGS) $(shell pkg-config --silence-errors --libs libprotobuf-mutator)

CORPUS_DUMP_PROBABILITY := 25
TRACER := ckb-vm-syscall-tracer

DOCKER := docker
DOCKER_IMAGE := docker.io/xxuejie/ckb-script-fuzzing-toolkit:20250410
DOCKER_RUN_ARGS :=

FILES := $(shell find $(LOCK_DIR) -type f -name "*.h" -o -name "*.c")

all: prepare build

repl:
	$(DOCKER) run --rm -it $(DOCKER_RUN_ARGS) -v $(TOP):/code $(DOCKER_IMAGE) || true
	$(DOCKER) run --rm $(DOCKER_RUN_ARGS) -e UID=`id -u` -e GID=`id -g` \
		-v $(TOP):/code $(DOCKER_IMAGE) bash -c 'chown -R -f $$UID:$$GID target fuzzing'

prepare: fuzzing_syscalls_all_in_one.h binary_to_text_converter
	rm -rf $(cur_dir)/dumps $(cur_dir)/corpus
	DUMP_TXS_PATH=$(cur_dir)/dumps DUMP_PROBABILITY=$(CORPUS_DUMP_PROBABILITY) \
		cargo test --release -p validation-tests _c_
	DUMP_TXS_PATH=$(cur_dir)/dumps DUMP_PROBABILITY=$(CORPUS_DUMP_PROBABILITY) \
		cargo test --release -p multisig-tests _c
	$(TOP)/target/release/fuzzing-corpus-generator \
		--metadata-file $(LOCK_DIR)/build/$(C_SCRIPT_NAME)_metadata_stripped.json \
		--dumps $(cur_dir)/dumps \
		--output $(cur_dir)/corpus \
		--tracer $(TRACER)

build: root_llvm_fuzzer root_honggfuzz_fuzzer root_aflxx_fuzzer \
	leaf_llvm.complete leaf_honggfuzz.complete leaf_aflxx.complete

fuzzing_syscalls_all_in_one.h:
	curl -sSf https://raw.githubusercontent.com/xxuejie/ckb-script-fuzzing-toolkit/refs/heads/main/build_single_header.sh | sh

binary_to_text_converter: fuzzer.cc fuzzing_syscalls_all_in_one.h
	$(CLANGXX) $< -o $@ \
		$(COMMON_CFLAGS) -DCKB_FUZZING_DEFINE_BINARY_TO_TEXT_CONVERTER \
		$(LDFLAGS)

root_llvm_fuzzer.o: fuzzing_syscalls_all_in_one.h $(FILES)
	$(CLANG) $(SCRIPT_CFLAGS) $(LLVM_FUZZER_SETTINGS) \
		-c $(LOCK_DIR)/ckb-sphincsplus-root-lock.c -o $@

root_honggfuzz.o: fuzzing_syscalls_all_in_one.h $(FILES)
	$(HFUZZ_CLANG) $(SCRIPT_CFLAGS) $(HONGGFUZZ_SETTINGS) \
		-c $(LOCK_DIR)/ckb-sphincsplus-root-lock.c -o $@

root_aflxx.o: fuzzing_syscalls_all_in_one.h $(FILES)
	$(AFLXX_CLANG) $(SCRIPT_CFLAGS) $(AFLXX_SETTINGS) \
		-c $(LOCK_DIR)/ckb-sphincsplus-root-lock.c -o $@

root_llvm_fuzzer: root_llvm_fuzzer.o fuzzer.cc
	$(CLANGXX) $^ -o $@ $(LLVM_FUZZER_CFLAGS) $(LLVM_FUZZER_LDFLAGS) $(LLVM_FUZZER_SETTINGS)

root_honggfuzz_fuzzer: root_honggfuzz.o fuzzer.cc
	$(HFUZZ_CLANGXX) $^ -o $@ $(HONGGFUZZ_CFLAGS) $(LDFLAGS) $(HONGGFUZZ_SETTINGS)

root_aflxx_fuzzer: root_aflxx.o fuzzer.cc
	$(AFLXX_CLANGXX) $^ -o $@ $(AFLXX_CFLAGS) $(LDFLAGS) $(AFLXX_SETTINGS)

leaf_llvm.complete: fuzzer.cc $(DETECTING_SOURCES) $(HEADERS) $(FILES) $(LOCK_DIR)/build/params.txt fuzzing_syscalls_all_in_one.h
	@set -eu; \
	param_ids=$$(cat $(LOCK_DIR)/build/params.txt | cut -d" " -f1); \
	for param_id in $${param_ids}; do \
		param=$$(grep ^$${param_id} $(LOCK_DIR)/build/params.txt | head -1 | cut -d" " -f2); \
		if echo "$${param}" | grep "shake" - > /dev/null; then \
			srcs="$(COMPILING_NATIVE_SOURCES) $(COMPILING_SHAKE_SOURCES) $(LOCK_DIR)/ckb-sphincsplus-leaf-lock.c"; \
		elif echo "$${param}" | grep "sha2" - > /dev/null; then \
			srcs="$(COMPILING_NATIVE_SOURCES) $(COMPILING_SHA2_SOURCES) $(LOCK_DIR)/ckb-sphincsplus-leaf-lock.c"; \
		fi; \
		echo "Building leaf fuzzer with params id: $${param_id}, params: $${param}"; \
		rm -rf $(cur_dir)/leaf_llvm_intermediate; \
		mkdir -p $(cur_dir)/leaf_llvm_intermediate; \
		set -x; \
		for src in $${srcs}; do \
			$(CLANG) $(SCRIPT_CFLAGS) $(LLVM_FUZZER_SETTINGS) \
				-DPARAMS_ID=$${param_id} -DPARAMS=$${param} \
				-c $${src} -o $(cur_dir)/leaf_llvm_intermediate/$$(basename $${src}).o; \
		done; \
		$(CLANGXX) fuzzer.cc $$(find leaf_llvm_intermediate -name "*.o") \
			-o $${param}_llvm_fuzzer \
			$(LLVM_FUZZER_CFLAGS) $(LLVM_FUZZER_LDFLAGS) $(LLVM_FUZZER_SETTINGS); \
		set +x; \
		rm -rf $(cur_dir)/leaf_llvm_intermediate; \
	done;
	touch $@

leaf_honggfuzz.complete: fuzzer.cc $(DETECTING_SOURCES) $(HEADERS) $(FILES) $(LOCK_DIR)/build/params.txt fuzzing_syscalls_all_in_one.h
	@set -eu; \
	param_ids=$$(cat $(LOCK_DIR)/build/params.txt | cut -d" " -f1); \
	for param_id in $${param_ids}; do \
		param=$$(grep ^$${param_id} $(LOCK_DIR)/build/params.txt | head -1 | cut -d" " -f2); \
		if echo "$${param}" | grep "shake" - > /dev/null; then \
			srcs="$(COMPILING_NATIVE_SOURCES) $(COMPILING_SHAKE_SOURCES) $(LOCK_DIR)/ckb-sphincsplus-leaf-lock.c"; \
		elif echo "$${param}" | grep "sha2" - > /dev/null; then \
			srcs="$(COMPILING_NATIVE_SOURCES) $(COMPILING_SHA2_SOURCES) $(LOCK_DIR)/ckb-sphincsplus-leaf-lock.c"; \
		fi; \
		echo "Building leaf fuzzer with params id: $${param_id}, params: $${param}"; \
		rm -rf $(cur_dir)/leaf_honggfuzz_intermediate; \
		mkdir -p $(cur_dir)/leaf_honggfuzz_intermediate; \
		set -x; \
		for src in $${srcs}; do \
			$(HFUZZ_CLANG) $(SCRIPT_CFLAGS) $(HONGGFUZZ_SETTINGS) \
				-DPARAMS_ID=$${param_id} -DPARAMS=$${param} \
				-c $${src} -o $(cur_dir)/leaf_honggfuzz_intermediate/$$(basename $${src}).o; \
		done; \
		$(HFUZZ_CLANGXX) fuzzer.cc $$(find leaf_honggfuzz_intermediate -name "*.o") \
			-o $${param}_honggfuzz_fuzzer \
			$(HONGGFUZZ_CFLAGS) $(LDFLAGS) $(HONGGFUZZ_SETTINGS); \
		set +x; \
		rm -rf $(cur_dir)/leaf_honggfuzz_intermediate; \
	done;
	touch $@

leaf_aflxx.complete: fuzzer.cc $(DETECTING_SOURCES) $(HEADERS) $(FILES) $(LOCK_DIR)/build/params.txt fuzzing_syscalls_all_in_one.h
	@set -eu; \
	param_ids=$$(cat $(LOCK_DIR)/build/params.txt | cut -d" " -f1); \
	for param_id in $${param_ids}; do \
		param=$$(grep ^$${param_id} $(LOCK_DIR)/build/params.txt | head -1 | cut -d" " -f2); \
		if echo "$${param}" | grep "shake" - > /dev/null; then \
			srcs="$(COMPILING_NATIVE_SOURCES) $(COMPILING_SHAKE_SOURCES) $(LOCK_DIR)/ckb-sphincsplus-leaf-lock.c"; \
		elif echo "$${param}" | grep "sha2" - > /dev/null; then \
			srcs="$(COMPILING_NATIVE_SOURCES) $(COMPILING_SHA2_SOURCES) $(LOCK_DIR)/ckb-sphincsplus-leaf-lock.c"; \
		fi; \
		echo "Building leaf fuzzer with params id: $${param_id}, params: $${param}"; \
		rm -rf $(cur_dir)/leaf_aflxx_intermediate; \
		mkdir -p $(cur_dir)/leaf_aflxx_intermediate; \
		set -x; \
		for src in $${srcs}; do \
			$(AFLXX_CLANG) $(SCRIPT_CFLAGS) $(AFLXX_SETTINGS) \
				-DPARAMS_ID=$${param_id} -DPARAMS=$${param} \
				-c $${src} -o $(cur_dir)/leaf_aflxx_intermediate/$$(basename $${src}).o; \
		done; \
		$(AFLXX_CLANGXX) fuzzer.cc $$(find leaf_aflxx_intermediate -name "*.o") \
			-o $${param}_aflxx_fuzzer \
			$(AFLXX_CFLAGS) $(LDFLAGS) $(AFLXX_SETTINGS); \
		set +x; \
		rm -rf $(cur_dir)/leaf_aflxx_intermediate; \
	done;
	touch $@

clean:
	rm -rf *.o *_fuzzer fuzzing_syscalls_all_in_one.h \
		dumps corpus* binary_to_text_converter leaf*.complete leaf*immediate
.PHONY: build clean prepare repl
