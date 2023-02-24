TARGET := riscv64-unknown-linux-gnu-
CC := $(TARGET)gcc
LD := $(TARGET)gcc

PARAMS = sphincs-shake-256f
THASH = robust

CFLAGS := -fPIC -O3 -fno-builtin-printf -fno-builtin-memcmp -nostdinc -nostartfiles -fvisibility=hidden -fdata-sections -ffunction-sections -nostdlib -Wno-nonnull-compare -DCKB_VM -DCKB_DECLARATION_ONLY
LDFLAGS := -fdata-sections -ffunction-sections

# Using a new version of gcc will have a warning of ckb-c-stdlib
CFLAGS := $(CFLAGS) -w
# CFLAGS := $(CFLAGS) -Wall -Werror -Wno-nonnull  -Wno-unused-function
LDFLAGS := $(LDFLAGS) -Wl,-static -Wl,--gc-sections

CFLAGS := $(CFLAGS) -I c -I deps/ckb-c-stdlib/libc -I deps/ckb-c-stdlib -I deps/ckb-c-stdlib/molecule
CFLAGS := $(CFLAGS) -I deps/sphincsplus/ref -DPARAMS=$(PARAMS)

SPHINCS_PLUS_DIR = deps/sphincsplus/ref/

SOURCES = \
	$(SPHINCS_PLUS_DIR)address.c \
	$(SPHINCS_PLUS_DIR)merkle.c \
	$(SPHINCS_PLUS_DIR)wots.c \
	$(SPHINCS_PLUS_DIR)wotsx1.c \
	$(SPHINCS_PLUS_DIR)utils.c \
	$(SPHINCS_PLUS_DIR)utilsx1.c \
	$(SPHINCS_PLUS_DIR)fors.c \
	$(SPHINCS_PLUS_DIR)sign.c \
	c/ckb-sphincsplus.c

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
	c/ckb-sphincsplus.h

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

CFLAGS := $(CFLAGS) -g -DCKB_C_STDLIB_PRINTF

# docker pull nervos/ckb-riscv-gnu-toolchain:gnu-jammy-20230214
BUILDER_DOCKER := nervos/ckb-riscv-gnu-toolchain@sha256:7601a814be2595ad471288fefc176356b31101837a514ddb0fc93b11c1cf5135

all: build/sphincsplus_lock

all-via-docker:
	docker run --rm -v `pwd`:/code ${BUILDER_DOCKER} bash -c "cd /code && make"

build/convert_asm: c/ref/fips202_asm.S
	riscv-naive-assembler -i c/ref/fips202_asm.S > c/ref/fips202_asm_bin.S

build/sphincsplus_lock: c/ckb-sphincsplus-lock.c $(SOURCES) $(HEADERS)
	mkdir -p build
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $<

clean:
	rm -rf build/sphincsplus_lock