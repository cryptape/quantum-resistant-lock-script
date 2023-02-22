
# Generate code, user performance analysis
CC=clang
LLVM_PROFDATA=llvm-profdata
LLVM_COV=llvm-cov

NPROC?=16

SOURCES_DIR = ref
COVERAGE_DIR=coverage
CORPUS_DIR=corpus

SOURCES = \
	../../../c/$(SOURCES_DIR)/params.c \
	../../../c/$(SOURCES_DIR)/address.c \
	../../../c/$(SOURCES_DIR)/merkle.c \
	../../../c/$(SOURCES_DIR)/wots.c \
	../../../c/$(SOURCES_DIR)/wotsx1.c \
	../../../c/$(SOURCES_DIR)/utils.c \
	../../../c/$(SOURCES_DIR)/utilsx1.c \
	../../../c/$(SOURCES_DIR)/fors.c \
	../../../c/$(SOURCES_DIR)/sign.c \
	../../../c/$(SOURCES_DIR)/randombytes.c \
	../../../c/ckb-sphincsplus.c

HEADERS = \
	../../../c/$(SOURCES_DIR)/params.h \
	../../../c/$(SOURCES_DIR)/address.h \
	../../../c/$(SOURCES_DIR)/merkle.h \
	../../../c/$(SOURCES_DIR)/wots.h \
	../../../c/$(SOURCES_DIR)/wotsx1.h \
	../../../c/$(SOURCES_DIR)/utils.h \
	../../../c/$(SOURCES_DIR)/utilsx1.h \
	../../../c/$(SOURCES_DIR)/fors.h \
	../../../c/$(SOURCES_DIR)/api.h \
	../../../c/$(SOURCES_DIR)/hash.h \
	../../../c/$(SOURCES_DIR)/thash.h \
	../../../c/$(SOURCES_DIR)/randombytes.h \
	../../../c/ckb-sphincsplus.h

# shake
SOURCES += \
	../../../c/$(SOURCES_DIR)/fips202.c \
	../../../c/$(SOURCES_DIR)/hash_shake.c \
	../../../c/$(SOURCES_DIR)/thash_shake_robust.c\
	../../../c/$(SOURCES_DIR)/thash_shake_simple.c
HEADERS += \
	../../../c/$(SOURCES_DIR)/fips202.h

# sha2
SOURCES += \
	../../../c/$(SOURCES_DIR)/sha2.c \
	../../../c/$(SOURCES_DIR)/hash_sha2.c \
	../../../c/$(SOURCES_DIR)/thash_sha2_robust.c \
	../../../c/$(SOURCES_DIR)/thash_sha2_simple.c
HEADERS += \
	../../../c/$(SOURCES_DIR)/sha2.h

# haraka
SOURCES += \
	../../../c/$(SOURCES_DIR)/haraka.c \
	../../../c/$(SOURCES_DIR)/hash_haraka.c \
	../../../c/$(SOURCES_DIR)/thash_haraka_robust.c \
	../../../c/$(SOURCES_DIR)/thash_haraka_simple.c
HEADERS += \
	../../../c/$(SOURCES_DIR)/haraka.h

FUZZER_FLAGS=-g -O1 -fsanitize=fuzzer,address,undefined -fsanitize-recover=address
FUZZER_FLAGS := $(FUZZER_FLAGS) -I ../../../c -I ../../../c/ref

COVERAGE_FLAGS=-fprofile-instr-generate -fcoverage-mapping
COVERAGE_FLAGS := $(COVERAGE_FLAGS) -I ../../../c -I ../../../c/ref

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