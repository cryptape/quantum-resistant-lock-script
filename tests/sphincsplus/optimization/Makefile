TARGET := riscv64-unknown-linux-gnu-
CC := $(TARGET)gcc
LD := $(TARGET)gcc

PARAMS = sphincs-shake-128f
THASH = simple

CFLAGS := -fPIC -O3 -fno-builtin-printf -fno-builtin-memcmp -nostdinc -nostartfiles -fvisibility=hidden -fdata-sections -ffunction-sections -nostdlib -Wno-nonnull-compare -DCKB_VM -DCKB_DECLARATION_ONLY -g -DCKB_C_STDLIB_PRINTF
LDFLAGS := -fdata-sections -ffunction-sections

# Using a new version of gcc will have a warning of ckb-c-stdlib
CFLAGS := $(CFLAGS) -w
# CFLAGS := $(CFLAGS) -Wall -Werror -Wno-nonnull  -Wno-unused-function
LDFLAGS := $(LDFLAGS) -Wl,-static -Wl,--gc-sections

CFLAGS := $(CFLAGS) -I ../../../c -I ../../../deps/ckb-c-stdlib/libc -I ../../../deps/ckb-c-stdlib -I ../../../deps/ckb-c-stdlib/molecule -I ../
CFLAGS := $(CFLAGS) -I ../../../deps/sphincsplus/ref -DPARAMS=$(PARAMS) -DTEST_DATA=$(PARAMS)-$(THASH)

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

# docker pull nervos/ckb-riscv-gnu-toolchain:gnu-jammy-20230214
BUILDER_DOCKER := nervos/ckb-riscv-gnu-toolchain@sha256:7601a814be2595ad471288fefc176356b31101837a514ddb0fc93b11c1cf5135

all: build/verify

all-via-docker:
	cd ../../../ && docker run --rm -v `pwd`:/code ${BUILDER_DOCKER} bash -c "cd /code/tests/sphincsplus/optimization && make PARAMS=$(PARAMS) THASH=$(THASH)"

build/verify: optimization-sphincsplus.c $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $<

run: build/verify
	export RUST_LOG=debug
	ckb-debugger --bin $< --max-cycles=10000000000

FLAME_GRAPH_DIR := ~/code/tmp/FlameGraph/

ppref: build/verify
	ckb-debugger --bin $< --max-cycles=10000000000 --pprof build/sphincsplus.pref
	$(FLAME_GRAPH_DIR)/flamegraph.pl build/sphincsplus.pref > build/sphincsplus.svg

clean:
	rm -rf build/*