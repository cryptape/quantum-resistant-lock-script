cur_dir = $(dir $(abspath $(firstword $(MAKEFILE_LIST))))

CLANG := clang-18
TOP := $(cur_dir)/../..

PARAMS = sphincs-shake-256f
THASH = robust

CFLAGS := -fPIC -O3 -fno-builtin-printf -fno-builtin-memcmp -fvisibility=hidden -fdata-sections -ffunction-sections -DCKB_DECLARATION_ONLY
LDFLAGS := -fdata-sections -ffunction-sections

CFLAGS := $(CFLAGS) -Wall -Werror -Wno-nonnull  -Wno-unused-function -g
LDFLAGS := $(LDFLAGS) -Wl,-static -Wl,--gc-sections
CFLAGS := $(CFLAGS) -fsanitize=address -fsanitize=undefined

SPHINCS_PLUS_DIR := $(TOP)/deps/sphincsplus/ref
LOCK_DIR := $(TOP)/contracts/c-sphincs-all-in-one-lock
CFLAGS := $(CFLAGS) -I $(LOCK_DIR) -I $(SPHINCS_PLUS_DIR) -DPARAMS=$(PARAMS) -DTEST_DATA=$(PARAMS)-$(THASH)

include $(TOP)/mk/files.mk

SOURCES = $(COMPILING_SOURCES_BY_PARAMS) $(SPHINCS_PLUS_DIR)/randombytes.c

all: build/test_sphincsplus

build/test_sphincsplus: test-ckb-sphincs-plus.c $(SOURCES) $(HEADERS)
	mkdir -p build
	$(CLANG) $(CFLAGS) -o $@ $(SOURCES) $<

clean:
	rm -rf build/test_sphincsplus
