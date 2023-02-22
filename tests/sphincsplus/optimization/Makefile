TARGET := riscv64-unknown-linux-gnu-
CC := $(TARGET)gcc
LD := $(TARGET)gcc

CFLAGS := -fPIC -O3 -fno-builtin-printf -fno-builtin-memcmp -nostdinc -nostartfiles -fvisibility=hidden -fdata-sections -ffunction-sections -nostdlib -Wno-nonnull-compare -DCKB_VM -DCKB_DECLARATION_ONLY
LDFLAGS := -fdata-sections -ffunction-sections

CFLAGS := $(CFLAGS) -Wall -Werror -Wno-nonnull  -Wno-unused-function
LDFLAGS := $(LDFLAGS) -Wl,-static -Wl,--gc-sections

CFLAGS := $(CFLAGS) -I ../../../c -I ../../../c/ref -I ../ -I ../../../deps/ckb-c-stdlib/libc -I ../../../deps/ckb-c-stdlib

CFLAGS := $(CFLAGS) -g -DCKB_C_STDLIB_PRINTF

SOURCES_DIR = ../../../c/ref/

SOURCES = \
	$(SOURCES_DIR)/params.c \
	$(SOURCES_DIR)/address.c \
	$(SOURCES_DIR)/merkle.c \
	$(SOURCES_DIR)/wots.c \
	$(SOURCES_DIR)/wotsx1.c \
	$(SOURCES_DIR)/utils.c \
	$(SOURCES_DIR)/utilsx1.c \
	$(SOURCES_DIR)/fors.c \
	$(SOURCES_DIR)/sign.c \
	$(SOURCES_DIR)/randombytes.c \
	$(SOURCES_DIR)/../ckb-sphincsplus.c

HEADERS = \
	$(SOURCES_DIR)params.h \
	$(SOURCES_DIR)address.h \
	$(SOURCES_DIR)merkle.h \
	$(SOURCES_DIR)wots.h \
	$(SOURCES_DIR)wotsx1.h \
	$(SOURCES_DIR)utils.h \
	$(SOURCES_DIR)utilsx1.h \
	$(SOURCES_DIR)fors.h \
	$(SOURCES_DIR)api.h \
	$(SOURCES_DIR)hash.h \
	$(SOURCES_DIR)thash.h \
	$(SOURCES_DIR)randombytes.h \
	$(SOURCES_DIR)/../ckb-sphincsplus.h

# shake
SOURCES += \
	$(SOURCES_DIR)fips202.c \
	$(SOURCES_DIR)hash_shake.c \
	$(SOURCES_DIR)thash_shake_robust.c \
	$(SOURCES_DIR)thash_shake_simple.c \
	$(SOURCES_DIR)fips202_asm_bin.S
HEADERS += \
	$(SOURCES_DIR)fips202.h

SOURCES += \
	$(SOURCES_DIR)haraka.c \
	$(SOURCES_DIR)hash_haraka.c \
	$(SOURCES_DIR)thash_haraka_robust.c \
	$(SOURCES_DIR)thash_haraka_simple.c
HEADERS += \
	$(SOURCES_DIR)haraka.h

SOURCES += \
	$(SOURCES_DIR)sha2.c \
	$(SOURCES_DIR)hash_sha2.c \
	$(SOURCES_DIR)thash_sha2_robust.c \
	$(SOURCES_DIR)thash_sha2_simple.c
HEADERS += \
	$(SOURCES_DIR)sha2.h

all: build/verify

build_asm: $(SOURCES_DIR)fips202_asm.S
	cd ../../../ && make build/convert_asm

build/verify: optimization-sphincsplus.c $(SOURCES) $(HEADERS) build_asm
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $<

run: build/verify
	ckb-debugger --bin $< --max-cycles=10000000000

FLAME_GRAPH_DIR := ~/code/tmp/FlameGraph/

ppref: build/verify
	ckb-debugger --bin $< --max-cycles=10000000000 --pprof build/sphincsplus.pref
	$(FLAME_GRAPH_DIR)/flamegraph.pl build/sphincsplus.pref > build/sphincsplus.svg

clean:
	rm -rf build/*