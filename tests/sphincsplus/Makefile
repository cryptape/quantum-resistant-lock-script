CC := clang-16

PARAMS = sphincs-shake-256f
THASH = robust

CFLAGS := -fPIC -O0 -fno-builtin-printf -fno-builtin-memcmp -fvisibility=hidden -fdata-sections -ffunction-sections -DCKB_DECLARATION_ONLY
LDFLAGS := -fdata-sections -ffunction-sections

CFLAGS := $(CFLAGS) -Wall -Werror -Wno-nonnull  -Wno-unused-function -g
LDFLAGS := $(LDFLAGS) -Wl,-static -Wl,--gc-sections
CFLAGS := $(CFLAGS) -fsanitize=address -fsanitize=undefined

CFLAGS := $(CFLAGS) -I c -I deps/sphincsplus/ref -DPARAMS=$(PARAMS) -DTEST_DATA=$(PARAMS)-$(THASH)
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
	$(SPHINCS_PLUS_DIR)randombytes.c \
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

all: build/test_sphincsplus

build/test_sphincsplus: tests/sphincsplus/test-ckb-sphincs-plus.c $(SOURCES) $(HEADERS)
	mkdir -p build
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $<

clean:
	rm -rf build/test_sphincsplus
