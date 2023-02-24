
# Generate code, user performance analysis
CC=clang
LLVM_PROFDATA=llvm-profdata
LLVM_COV=llvm-cov

NPROC?=16

PARAMS = sphincs-shake-256f
THASH = robust

SOURCES_DIR = ref
COVERAGE_DIR=coverage
CORPUS_DIR=corpus

SPHINCS_PLUS_DIR = ../../../deps/sphincsplus/ref/

SOURCES = \
	$(SPHINCS_PLUS_DIR)address.c \
	$(SPHINCS_PLUS_DIR)merkle.c \
	$(SPHINCS_PLUS_DIR)wots.c \
	$(SPHINCS_PLUS_DIR)wotsx1.c \
	$(SPHINCS_PLUS_DIR)utils.c \
	$(SPHINCS_PLUS_DIR)utilsx1.c \
	$(SPHINCS_PLUS_DIR)fors.c \
	$(SPHINCS_PLUS_DIR)sign.c \
	$(SPHINCS_PLUS_DIR)randombytes.c \
	../../../c/ckb-sphincsplus.c

HEADERS = \
	$(SPHINCS_PLUS_DIR)params.h \
	$(SPHINCS_PLUS_DIR)address.h \
	$(SPHINCS_PLUS_DIR)merkle.h \
	$(SPHINCS_PLUS_DIR)wots.h \
	$(SPHINCS_PLUS_DIR)wotsx1.h \
	$(SPHINCS_PLUS_DIR)utils.h \
	$(SPHINCS_PLUS_DIR)utilsx1.h \
	$(SPHINCS_PLUS_DIR)fors.h \
	$(SPHINCS_PLUS_DIR)api.h \
	$(SPHINCS_PLUS_DIR)hash.h \
	$(SPHINCS_PLUS_DIR)thash.h \
	$(SPHINCS_PLUS_DIR)randombytes.h \
	../../../c/ckb-sphincsplus.h

ifneq (,$(findstring shake,$(PARAMS)))
	SOURCES += \
		$(SPHINCS_PLUS_DIR)fips202.c \
		$(SPHINCS_PLUS_DIR)hash_shake.c \
		$(SPHINCS_PLUS_DIR)thash_shake_$(THASH).c
	HEADERS += $(SPHINCS_PLUS_DIR)fips202.h
endif
ifneq (,$(findstring haraka,$(PARAMS)))
	SOURCES += \
		$(SPHINCS_PLUS_DIR)haraka.c \
		$(SPHINCS_PLUS_DIR)hash_haraka.c \
		$(SPHINCS_PLUS_DIR)thash_haraka_$(THASH).c
	HEADERS += $(SPHINCS_PLUS_DIR)haraka.h
endif
ifneq (,$(findstring sha2,$(PARAMS)))
	SOURCES += \
		$(SPHINCS_PLUS_DIR)sha2.c \
		$(SPHINCS_PLUS_DIR)hash_sha2.c \
		$(SPHINCS_PLUS_DIR)thash_sha2_$(THASH).c
	HEADERS += $(SPHINCS_PLUS_DIR)sha2.h
endif

FUZZER_FLAGS=-g -O1 -fsanitize=fuzzer,address,undefined -fsanitize-recover=address -DPARAMS=$(PARAMS) -DTEST_DATA=$(PARAMS)-$(THASH)
FUZZER_FLAGS := $(FUZZER_FLAGS) -I ../../../c -I ../../../deps/sphincsplus/ref

COVERAGE_FLAGS=-fprofile-instr-generate -fcoverage-mapping -DPARAMS=$(PARAMS) -DTEST_DATA=$(PARAMS)-$(THASH)
COVERAGE_FLAGS := $(COVERAGE_FLAGS) -I ../../../c -I ../../../deps/sphincsplus/ref

ifeq ($(OS),MacOS)
	COVERAGE_FLAGS+=-Wl,-U,_LLVMFuzzerCustomMutator -Wl,-U,_LLVMFuzzerInitialize
endif

EXTERNAL_HEADERS=../../../deps/ckb-c-stdlib-20210801/ckb_exec.h

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
	$(LLVM_COV) report --show-functions --instr-profile=$(COVERAGE_DIR)/fuzzer.profdata build/cover $(EXTERNAL_HEADERS)

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