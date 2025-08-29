cur_dir = $(dir $(abspath $(firstword $(MAKEFILE_LIST))))
TOP := $(cur_dir)/../../..

# Generate code, user performance analysis
CLANG := $(shell $(TOP)/scripts/find_clang)
LLVM_PROFDATA := $(subst clang,llvm-profdata,$(CC))
LLVM_COV := $(subst clang,llvm-cov,$(CC))

NPROC?=16

PARAMS = sphincs-shake-256f
THASH = robust

COVERAGE_DIR=coverage
CORPUS_DIR=corpus

LOCK_DIR := $(TOP)/contracts/c-sphincs-all-in-one-lock
SPHINCS_PLUS_DIR := $(TOP)/deps/sphincsplus/ref
CKB_STDLIB_DIR := $(TOP)/deps/ckb-c-stdlib

include $(TOP)/mk/files.mk

SOURCES = $(COMPILING_SOURCES_BY_PARAMS) $(SPHINCS_PLUS_DIR)/randombytes.c

FUZZER_FLAGS=-g -O1 -fsanitize=fuzzer,address,undefined -fsanitize-recover=address -DPARAMS=$(PARAMS) -DTEST_DATA=$(PARAMS)-$(THASH)
FUZZER_FLAGS := $(FUZZER_FLAGS) -I $(LOCK_DIR) -I $(SPHINCS_PLUS_DIR)

COVERAGE_FLAGS=-fprofile-instr-generate -fcoverage-mapping -DPARAMS=$(PARAMS) -DTEST_DATA=$(PARAMS)-$(THASH)
COVERAGE_FLAGS := $(COVERAGE_FLAGS) -I $(LOCK_DIR) -I $(SPHINCS_PLUS_DIR)

ifeq ($(OS),MacOS)
	COVERAGE_FLAGS+=-Wl,-U,_LLVMFuzzerCustomMutator -Wl,-U,_LLVMFuzzerInitialize
endif

EXTERNAL_HEADERS=$(TOP)/deps/ckb-c-stdlib/ckb_exec.h

all: build/fuzzer build/cover

build/fuzzer: sphincs_plus_fuzzer.c $(SOURCES) $(HEADERS)
	mkdir -p build
	$(CC) $(FUZZER_FLAGS) -o $@ $(SOURCES) $<

build/cover: sphincs_plus_cover.c sphincs_plus_fuzzer.c $(SOURCES) $(HEADERS)
	$(CC) $(COVERAGE_FLAGS) -o $@ $(SOURCES) $< sphincs_plus_fuzzer.c

start-fuzzer: build/fuzzer
	cd build && mkdir -p $(CORPUS_DIR)
	cd build && ./fuzzer -max_len=8000000 -jobs=$(NPROC) $(CORPUS_DIR)

show: build/$(COVERAGE_DIR)/fuzzer.profdata
	cd build && mkdir -p $(COVERAGE_DIR)
	cd build && $(LLVM_COV) show --instr-profile=$(COVERAGE_DIR)/fuzzer.profdata cover

report: build/$(COVERAGE_DIR)/fuzzer.profdata build/cover $(EXTERNAL_HEADERS)
	$(LLVM_COV) report --instr-profile=build/$(COVERAGE_DIR)/fuzzer.profdata build/cover $(EXTERNAL_HEADERS)

%.profraw: build/cover
	LLVM_PROFILE_FILE=$@ build/cover build/$(CORPUS_DIR)/*

%.profdata: %.profraw
	$(LLVM_PROFDATA) merge --sparse $< -o $@

.PRECIOUS: build/$(COVERAGE_DIR)/fuzzer.profraw build/$(COVERAGE_DIR)/fuzzer.profdata

clean:
	rm -rf build/*

clean-fuzzer:
	rm -rf build/corpus
	rm -rf build/fuzz-*.log
