# We cannot use $(shell pwd), which will return unix path format on Windows,
# making it hard to use.
cur_dir = $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

TOP := $(cur_dir)
MODE := release
# Tweak this to change the clang version to use for building C code. By default
# we use a bash script with somes heuristics to find clang in current system.
CLANG := $(shell $(TOP)/scripts/find_clang)
OBJCOPY := $(subst clang,llvm-objcopy,$(CLANG))
CLANG_FORMAT := $(subst clang,clang-format,$(CLANG))
# When this is set to some value, the generated binaries will be copied over
BUILD_DIR :=
# Generated binaries to copy. By convention, a Rust crate's directory name will
# likely match the crate name, which is also the name of the final binary.
# However if this is not the case, you can tweak this variable. As the name hints,
# more than one binary is supported here.
BINARY := $(notdir $(shell pwd))

ifeq (release,$(MODE))
	MODE_ARGS := -Os
endif

# Sphincs+ lock specific sections
OBJCOPY := $(subst clang,llvm-objcopy,$(CLANG))
CLANG_FORMAT := $(subst clang,clang-format,$(CLANG))

# Local build directory
CUR_BUILD := $(cur_dir)/build
SPHINCS_PLUS_DIR := $(TOP)/deps/sphincsplus/ref

PARAMS_DEFINITION_FILE := $(TOP)/params.txt
ALL_PARAM_IDS := $(shell cat $(PARAMS_DEFINITION_FILE) | cut -d" " -f1)

CFLAGS := -g $(MODE_ARGS) -fPIC \
		-Wall -Werror -Wno-nonnull -Wno-unused-function \
		-Wno-error=unused-but-set-variable \
		-Wno-error=unused-command-line-argument \
		-Wno-error=bitwise-instead-of-logical \
		-fno-builtin-printf -fno-builtin-memcmp \
		-fvisibility=hidden \
		-fdata-sections -ffunction-sections

CFLAGS += --target=riscv64 -march=rv64imc_zba_zbb_zbc_zbs \
	-DCKB_VM -DCKB_DECLARATION_ONLY \
	-nostdinc -nostdlib -I $(TOP)/deps/ckb-c-stdlib/libc \
	-I $(TOP)/deps/ckb-c-stdlib
CFLAGS += -I $(SPHINCS_PLUS_DIR) -I $(CUR_BUILD) -I $(cur_dir)/utils
# CFLAGS += -DCKB_C_STDLIB_PRINTF

LDFLAGS := -static -Wl,--gc-sections

SOURCES = \
	$(SPHINCS_PLUS_DIR)/address.c \
	$(SPHINCS_PLUS_DIR)/merkle.c \
	$(SPHINCS_PLUS_DIR)/wots.c \
	$(SPHINCS_PLUS_DIR)/wotsx1.c \
	$(SPHINCS_PLUS_DIR)/utils.c \
	$(SPHINCS_PLUS_DIR)/utilsx1.c \
	$(SPHINCS_PLUS_DIR)/fors.c \
	$(SPHINCS_PLUS_DIR)/sign.c \
	ckb-sphincsplus.c

HEADERS = \
	$(SPHINCS_PLUS_DIR)/params.h \
	$(SPHINCS_PLUS_DIR)/address.h \
	$(SPHINCS_PLUS_DIR)/merkle.h \
	$(SPHINCS_PLUS_DIR)/wots.h \
	$(SPHINCS_PLUS_DIR)/wotsx1.h \
	$(SPHINCS_PLUS_DIR)/utils.h \
	$(SPHINCS_PLUS_DIR)/utilsx1.h \
	$(SPHINCS_PLUS_DIR)/fors.h \
	$(SPHINCS_PLUS_DIR)/api.h \
	$(SPHINCS_PLUS_DIR)/hash.h \
	$(SPHINCS_PLUS_DIR)/thash.h \
	$(SPHINCS_PLUS_DIR)/randombytes.h \
	ckb-sphincsplus.h \
	ckb-sphincsplus-common.h \
	$(wildcard utils/*.h)

default: build

build: $(CUR_BUILD)/$(BINARY)
	cp $(CUR_BUILD)/$(BINARY) $(TOP)/$(BUILD_DIR)
	cp $(CUR_BUILD)/$(BINARY).debug $(TOP)/$(BUILD_DIR)

$(CUR_BUILD)/$(BINARY): $(CUR_BUILD)/root.complete $(CUR_BUILD)/leaf.complete
	$(TOP)/target/$(MODE)/patch-root-binary --root-debug-binary $(CUR_BUILD)/root.debug \
		--root-actual-binary $(CUR_BUILD)/root.debug \
		--leaf-binary-template $(CUR_BUILD)/leaf_@@.debug \
		--output-binary $@.debug \
		--params-file $(PARAMS_DEFINITION_FILE) \
		--merge
	$(TOP)/target/$(MODE)/patch-root-binary --root-debug-binary $(CUR_BUILD)/root.debug \
		--root-actual-binary $(CUR_BUILD)/root.stripped \
		--leaf-binary-template $(CUR_BUILD)/leaf_@@.stripped \
		--output-binary $@ \
		--params-file $(PARAMS_DEFINITION_FILE) \
		--merge

$(CUR_BUILD)/root.complete: ckb-sphincsplus-root-lock.c $(CUR_BUILD)/params-finder.h
	$(CLANG) $(CFLAGS) $(LDFLAGS) -o $(CUR_BUILD)/root.debug $<
	$(OBJCOPY) --strip-debug --strip-all $(CUR_BUILD)/root.debug $(CUR_BUILD)/root.stripped
	touch $@

$(CUR_BUILD)/leaf.complete: $(SOURCES) $(HEADERS) ckb-sphincsplus-leaf-lock.c
	mkdir -p $(CUR_BUILD)
	@set -eu; \
	for param_id in $(ALL_PARAM_IDS); do \
		param=$$(head -n $$param_id $(PARAMS_DEFINITION_FILE) | tail -1 | cut -d" " -f2); \
		if echo "$${param}" | grep "shake" - > /dev/null; then \
			others="$(SPHINCS_PLUS_DIR)/fips202.c $(SPHINCS_PLUS_DIR)/hash_shake.c"; \
			others="$${others} $(SPHINCS_PLUS_DIR)/thash_shake_simple.c"; \
		elif echo "$${param}" | grep "sha2" - > /dev/null; then \
			others="$(SPHINCS_PLUS_DIR)/sha2.c $(SPHINCS_PLUS_DIR)/hash_sha2.c"; \
			others="$${others} $(SPHINCS_PLUS_DIR)/thash_sha2_simple.c"; \
		fi; \
		echo "Building sphincs+ lock with params id: $${param_id}, params: $${param}"; \
		set -x; \
		$(CLANG) $(CFLAGS) $(LDFLAGS) -DPARAMS_ID=$${param_id} -DPARAMS=$${param} \
			-o $(CUR_BUILD)/leaf_$${param}.debug \
			$(SOURCES) $${others} ckb-sphincsplus-leaf-lock.c; \
		$(OBJCOPY) --strip-debug --strip-all \
			$(CUR_BUILD)/leaf_$${param}.debug \
			$(CUR_BUILD)/leaf_$${param}.stripped; \
		set +x; \
	done;
	touch $@

$(CUR_BUILD)/params-finder.h: $(HEADERS) $(CUR_BUILD)/aggregated-params.h
	mkdir -p $(CUR_BUILD)
	$(TOP)/target/$(MODE)/build-params-finder --params-file $(PARAMS_DEFINITION_FILE) > $@

$(CUR_BUILD)/aggregated-params.h: tools/extract-sphincs-params.c $(HEADERS)
	mkdir -p $(CUR_BUILD)
	rm -f $@
	@set -eu; \
	for param_id in $(ALL_PARAM_IDS); do \
		param=$$(head -n $$param_id $(PARAMS_DEFINITION_FILE) | tail -1 | cut -d" " -f2); \
		set -x; \
		$(CLANG) -g -O3 $< -o $(CUR_BUILD)/extract-params_$${param} \
			-DPARAMS_ID=$${param_id} -DPARAMS=$${param} \
			-I $(SPHINCS_PLUS_DIR) -I $(cur_dir); \
		$(CUR_BUILD)/extract-params_$${param} >> $@; \
		set +x; \
	done;

fmt:
	$(CLANG_FORMAT) -i --style='{BasedOnStyle: google, SortIncludes: false}' *.c *.h tools/*.c utils/*.h

clean:
	rm -rf $(CUR_BUILD)

.PHONY: build clean fmt
