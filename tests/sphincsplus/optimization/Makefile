cur_dir = $(dir $(abspath $(firstword $(MAKEFILE_LIST))))
TOP := $(cur_dir)/../../..

CC := clang-18

PARAMS = sphincs-shake-128f
THASH = simple

CFLAGS := -fPIC -Os -g -fno-builtin-printf -fno-builtin-memcmp \
	-fvisibility=hidden -fdata-sections -ffunction-sections \
	-Wno-nonnull-compare
CFLAGS += --target=riscv64 -march=rv64imc_zba_zbb_zbc_zbs \
	-nostdinc -nostdlib -nostartfiles -DCKB_VM -DCKB_DECLARATION_ONLY
CFLAGS += -DCKB_C_STDLIB_PRINTF
LDFLAGS := -fdata-sections -ffunction-sections

# Using a new version of gcc will have a warning of ckb-c-stdlib
CFLAGS := $(CFLAGS) -w
# CFLAGS := $(CFLAGS) -Wall -Werror -Wno-nonnull  -Wno-unused-function
LDFLAGS := $(LDFLAGS) -Wl,-static -Wl,--gc-sections

LOCK_DIR := $(TOP)/contracts/c-sphincs-all-in-one-lock
SPHINCS_PLUS_DIR := $(TOP)/deps/sphincsplus/ref
CKB_STDLIB_DIR := $(TOP)/deps/ckb-c-stdlib

CFLAGS := $(CFLAGS) -I $(LOCK_DIR) -I $(CKB_STDLIB_DIR) -I $(CKB_STDLIB_DIR)/libc -I $(CKB_STDLIB_DIR)/molecule -I ../
CFLAGS := $(CFLAGS) -I $(SPHINCS_PLUS_DIR) -DPARAMS=$(PARAMS) -DTEST_DATA=$(PARAMS)-$(THASH)

include $(TOP)/mk/files.mk

all: build/verify

build/verify: optimization-sphincsplus.c $(COMPILING_SOURCES_BY_PARAMS) $(HEADERS)
	mkdir -p build
	$(CC) $(CFLAGS) -o $@ $(COMPILING_SOURCES_BY_PARAMS) $<

run: build/verify
	export RUST_LOG=debug
	ckb-debugger --bin $< --max-cycles=10000000000

FLAME_GRAPH_BIN := ~/code/tmp/FlameGraph/flamegraph.pl

ppref: build/verify
	ckb-debugger --bin $< --max-cycles=10000000000 --pprof build/sphincsplus.pref
	$(FLAME_GRAPH_BIN) build/sphincsplus.pref > build/sphincsplus.svg

clean:
	rm -rf build/*
