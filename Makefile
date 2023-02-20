TARGET := 
TARGET := riscv64-unknown-linux-gnu-
CC := $(TARGET)gcc
LD := $(TARGET)gcc

CFLAGS := -fPIC -O3 -fno-builtin-printf -fno-builtin-memcmp -nostdinc -nostartfiles -fvisibility=hidden -fdata-sections -ffunction-sections -nostdlib -Wno-nonnull-compare -DCKB_VM -DCKB_DECLARATION_ONLY
LDFLAGS := -fdata-sections -ffunction-sections

CFLAGS := $(CFLAGS) -Wall -Werror -Wno-nonnull  -Wno-unused-function -g
LDFLAGS := $(LDFLAGS) -Wl,-static -Wl,--gc-sections

CFLAGS := $(CFLAGS) -I c -I deps/ckb-c-stdlib/libc -I deps/ckb-c-stdlib -I deps/ckb-c-stdlib/molecule
CFLAGS := $(CFLAGS) -I c/ref

SOURCES_DIR = ref

SOURCES = \
	c/$(SOURCES_DIR)/params.c \
	c/$(SOURCES_DIR)/address.c \
	c/$(SOURCES_DIR)/merkle.c \
	c/$(SOURCES_DIR)/wots.c \
	c/$(SOURCES_DIR)/wotsx1.c \
	c/$(SOURCES_DIR)/utils.c \
	c/$(SOURCES_DIR)/utilsx1.c \
	c/$(SOURCES_DIR)/fors.c \
	c/$(SOURCES_DIR)/sign.c \
	c/$(SOURCES_DIR)/randombytes.c \
	c/ckb-sphincsplus.c

HEADERS = \
	c/$(SOURCES_DIR)/params.h \
	c/$(SOURCES_DIR)/address.h \
	c/$(SOURCES_DIR)/merkle.h \
	c/$(SOURCES_DIR)/wots.h \
	c/$(SOURCES_DIR)/wotsx1.h \
	c/$(SOURCES_DIR)/utils.h \
	c/$(SOURCES_DIR)/utilsx1.h \
	c/$(SOURCES_DIR)/fors.h \
	c/$(SOURCES_DIR)/api.h \
	c/$(SOURCES_DIR)/hash.h \
	c/$(SOURCES_DIR)/thash.h \
	c/$(SOURCES_DIR)/randombytes.h \
	c/ckb-sphincsplus.h

# shake
SOURCES += \
	c/$(SOURCES_DIR)/fips202.c \
	c/$(SOURCES_DIR)/hash_shake.c \
	c/$(SOURCES_DIR)/thash_shake_robust.c\
	c/$(SOURCES_DIR)/thash_shake_simple.c
HEADERS += \
	c/$(SOURCES_DIR)/fips202.h

# sha2
SOURCES += \
	c/$(SOURCES_DIR)/sha2.c \
	c/$(SOURCES_DIR)/hash_sha2.c \
	c/$(SOURCES_DIR)/thash_sha2_robust.c \
	c/$(SOURCES_DIR)/thash_sha2_simple.c
HEADERS += \
	c/$(SOURCES_DIR)/sha2.h

# haraka
SOURCES += \
	c/$(SOURCES_DIR)/haraka.c \
	c/$(SOURCES_DIR)/hash_haraka.c \
	c/$(SOURCES_DIR)/thash_haraka_robust.c \
	c/$(SOURCES_DIR)/thash_haraka_simple.c
HEADERS += \
	c/$(SOURCES_DIR)/haraka.h

CFLAGS := $(CFLAGS) -DCKB_C_STDLIB_PRINTF

# docker pull nervos/ckb-riscv-gnu-toolchain:gnu-bionic-20191012
BUILDER_DOCKER := nervos/ckb-riscv-gnu-toolchain@sha256:aae8a3f79705f67d505d1f1d5ddc694a4fd537ed1c7e9622420a470d59ba2ec3

all: build/sphincsplus_lock

all-via-docker:
	docker run --rm -v `pwd`:/code ${BUILDER_DOCKER} bash -c "cd /code && make"

build/sphincsplus_lock: c/ckb-sphincsplus-lock.c $(SOURCES) $(HEADERS)
	mkdir -p build
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $<

clean:
	rm -rf build/sphincsplus_lock