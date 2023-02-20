
# Generate code, user performance analysis
CC=clang
LLVM_PROFDATA=llvm-profdata
LLVM_COV=llvm-cov

NPROC?=30

SOURCES_DIR = ref

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

all: build/fuzzer build/cover

build/fuzzer: sphincs_plus_fuzzer.c $(SOURCES) $(HEADERS)
	mkdir -p build
	$(CC) $(FUZZER_FLAGS) -o $@ $(SOURCES) $<

build/cover: sphincs_plus_cover.c sphincs_plus_fuzzer.c $(SOURCES) $(HEADERS)
	$(CC) $(COVERAGE_FLAGS) -o $@ $(SOURCES) $< sphincs_plus_fuzzer.c

start-fuzzer: build/fuzzer
	mkdir -p build/corpus
	cd build && ./fuzzer -max_len=8000000 -jobs=$(NPROC) corpus

clean:
	rm -rf build/*

clean-fuzzer:
	rm -rf build/corpus
	rm -rf build/fuzz-*.log