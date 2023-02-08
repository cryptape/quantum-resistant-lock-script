TARGET := 
TARGET := riscv64-unknown-linux-gnu-
CC := $(TARGET)gcc
LD := $(TARGET)gcc

PARAMS = sphincs-haraka-128f
THASH = robust

CFLAGS := -fPIC -O3 -fno-builtin-printf -fno-builtin-memcmp -nostdinc -nostartfiles -fvisibility=hidden -fdata-sections -ffunction-sections
LDFLAGS := -fdata-sections -ffunction-sections

ifneq ($(TARGET), )
	CFLAGS := $(CFLAGS) -nostdlib -Wno-nonnull-compare -DCKB_VM
else
	CFLAGS := -fsanitize=address -fsanitize=undefined
endif

CFLAGS := $(CFLAGS) -Wall -Werror -Wno-nonnull  -Wno-unused-function -g
LDFLAGS := $(LDFLAGS) -Wl,-static -Wl,--gc-sections

CFLAGS := $(CFLAGS) -I c -I deps/ckb-c-stdlib/libc -I deps/ckb-c-stdlib
CFLAGS := $(CFLAGS) -I c/ref

SOURCES_DIR = ref

SOURCES = \
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

ifneq (,$(findstring shake,$(PARAMS)))
	SOURCES += \
		c/$(SOURCES_DIR)/fips202.c \
		c/$(SOURCES_DIR)/hash_shake.c \
		c/$(SOURCES_DIR)/thash_shake_$(THASH).c
	HEADERS += \
		c/$(SOURCES_DIR)/fips202.h
endif
ifneq (,$(findstring haraka,$(PARAMS)))
	SOURCES += \
		c/$(SOURCES_DIR)/haraka.c \
		c/$(SOURCES_DIR)/hash_haraka.c \
		c/$(SOURCES_DIR)/thash_haraka_$(THASH).c
	HEADERS += \
		c/$(SOURCES_DIR)/haraka.h
endif
ifneq (,$(findstring sha2,$(PARAMS)))
	SOURCES += \
		c/$(SOURCES_DIR)/sha2.c \
		c/$(SOURCES_DIR)/hash_sha2.c \
		c/$(SOURCES_DIR)/thash_sha2_$(THASH).c
	HEADERS += \
		c/$(SOURCES_DIR)/sha2.h
endif

CFLAGS := $(CFLAGS) -DPARAMS=$(PARAMS) -DCKB_DECLARATION_ONLY -DCKB_C_STDLIB_PRINTF

build/sphincsplus_example: examples/ckb-sphincsplus-example.c $(SOURCES) $(HEADERS)
	mkdir -p build
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $<

clean:
	rm -rf build/sphincsplus_example