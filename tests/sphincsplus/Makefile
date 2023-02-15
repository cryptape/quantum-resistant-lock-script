CC := clang
LD := clang

PARAMS = sphincs-shake-256f
THASH = robust

CFLAGS := -fPIC -O0 -fno-builtin-printf -fno-builtin-memcmp -fvisibility=hidden -fdata-sections -ffunction-sections -DPARAMS=$(PARAMS) -DCKB_DECLARATION_ONLY
LDFLAGS := -fdata-sections -ffunction-sections

CFLAGS := $(CFLAGS) -Wall -Werror -Wno-nonnull  -Wno-unused-function -g
LDFLAGS := $(LDFLAGS) -Wl,-static -Wl,--gc-sections

CFLAGS := $(CFLAGS) -fsanitize=address -fsanitize=undefined

CFLAGS := $(CFLAGS) -I c
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

all: build/test_sphincsplus

all-via-docker:
	docker run --rm -v `pwd`:/code ${BUILDER_DOCKER} bash -c "cd /code && make"

build/test_sphincsplus: tests/sphincsplus/test-ckb-sphincs-plus.c $(SOURCES) $(HEADERS)
	mkdir -p build
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $<

clean:
	rm -rf build/test_sphincsplus