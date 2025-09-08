# We cannot use $(shell pwd), which will return unix path format on Windows,
# making it hard to use.
cur_dir = $(dir $(abspath $(firstword $(MAKEFILE_LIST))))

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
# FIPS 205 only approves simple THASH type
THASH = simple
LOCK_DIR := $(cur_dir)
SPHINCS_PLUS_DIR := $(TOP)/deps/sphincsplus/ref

include $(TOP)/mk/files.mk

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

OS := $(shell uname -s)
LDFLAGS :=
ifneq($(OS),Darwin)
	LDFLAGS += -static -Wl,--gc-sections
endif

default: build

build: $(CUR_BUILD)/$(BINARY) $(CUR_BUILD)/nist-vector-tester
	cp $(CUR_BUILD)/$(BINARY) $(TOP)/$(BUILD_DIR)
	cp $(CUR_BUILD)/$(BINARY).debug $(TOP)/$(BUILD_DIR)
	cp $(CUR_BUILD)/nist-vector-tester $(TOP)/$(BUILD_DIR)
	cp $(CUR_BUILD)/nist-vector-tester.debug $(TOP)/$(BUILD_DIR)

$(CUR_BUILD)/nist-vector-tester: nist-vector-tester.c $(CUR_BUILD)/params-finder.h $(CUR_BUILD)/leaf-vars.h $(CUR_BUILD)/leaf.complete $(HEADERS)
	$(CLANG) $(CFLAGS) $(LDFLAGS) -o $@-root.debug $<
	$(OBJCOPY) --strip-debug --strip-all $@-root.debug $@-root.stripped
	$(TOP)/target/$(MODE)/script-merge-tool --prefix CKB_ merge \
		--root-debug $@-root.debug \
		--root-actual $@-root.debug \
		--leaves $(CUR_BUILD)/leaves_debug \
		--output $@.debug \
		--metadata-file $@_metadata_debug.json \
		--merge
	$(TOP)/target/$(MODE)/script-merge-tool --prefix CKB_ merge \
		--root-debug $@-root.debug \
		--root-actual $@-root.stripped \
		--leaves $(CUR_BUILD)/leaves_stripped \
		--output $@ \
		--metadata-file $@_metadata_stripped.json \
		--merge

$(CUR_BUILD)/$(BINARY): $(CUR_BUILD)/root.complete $(CUR_BUILD)/leaf.complete $(HEADERS)
	$(TOP)/target/$(MODE)/script-merge-tool --prefix CKB_ merge \
		--root-debug $(CUR_BUILD)/root.debug \
		--root-actual $(CUR_BUILD)/root.debug \
		--leaves $(CUR_BUILD)/leaves_debug \
		--output $@.debug \
		--metadata-file $@_metadata_debug.json \
		--merge
	$(TOP)/target/$(MODE)/script-merge-tool --prefix CKB_ merge \
		--root-debug $(CUR_BUILD)/root.debug \
		--root-actual $(CUR_BUILD)/root.stripped \
		--leaves $(CUR_BUILD)/leaves_stripped \
		--output $@ \
		--metadata-file $@_metadata_stripped.json \
		--merge

$(CUR_BUILD)/root.complete: ckb-sphincsplus-root-lock.c $(CUR_BUILD)/params-finder.h $(CUR_BUILD)/leaf-vars.h
	$(CLANG) $(CFLAGS) $(LDFLAGS) -o $(CUR_BUILD)/root.debug $<
	$(OBJCOPY) --strip-debug --strip-all $(CUR_BUILD)/root.debug $(CUR_BUILD)/root.stripped
	touch $@

$(CUR_BUILD)/leaf-vars.h: $(TOP)/target/$(MODE)/script-merge-tool $(CUR_BUILD)/leaf.complete
	# leaf-vars.h only need script names, either debug or stripped directory will work,
	# no need to do it twice
	$< --prefix CKB_ generate \
		--leaves $(CUR_BUILD)/leaves_stripped \
		--language c \
		--output $@

$(CUR_BUILD)/leaf.complete: $(DETECTING_SOURCES) $(HEADERS) ckb-sphincsplus-leaf-lock.c $(CUR_BUILD)/params.txt
	mkdir -p $(CUR_BUILD)
	rm -rf $(CUR_BUILD)/leaves_debug $(CUR_BUILD)/leaves_stripped
	mkdir -p $(CUR_BUILD)/leaves_debug $(CUR_BUILD)/leaves_stripped
	@set -eu; \
	param_ids=$$(cat $(CUR_BUILD)/params.txt | cut -d" " -f1); \
	for param_id in $${param_ids}; do \
		param=$$(grep ^$${param_id} $(CUR_BUILD)/params.txt | head -1 | cut -d" " -f2); \
		if echo "$${param}" | grep "shake" - > /dev/null; then \
			srcs="$(COMPILING_COMMON_SOURCES) $(COMPILING_SHAKE_SOURCES)"; \
		elif echo "$${param}" | grep "sha2" - > /dev/null; then \
			srcs="$(COMPILING_COMMON_SOURCES) $(COMPILING_SHA2_SOURCES)"; \
		fi; \
		echo "Building sphincs+ lock with params id: $${param_id}, params: $${param}"; \
		set -x; \
		$(CLANG) $(CFLAGS) $(LDFLAGS) -DPARAMS_ID=$${param_id} -DPARAMS=$${param} \
			-o $(CUR_BUILD)/leaves_debug/$${param} \
			$${srcs} ckb-sphincsplus-leaf-lock.c; \
		$(OBJCOPY) --strip-debug --strip-all \
			$(CUR_BUILD)/leaves_debug/$${param} \
			$(CUR_BUILD)/leaves_stripped/$${param}; \
		set +x; \
	done;
	touch $@

$(CUR_BUILD)/params-finder.h: $(TOP)/target/$(MODE)/generate-c-params-finder $(HEADERS) $(CUR_BUILD)/aggregated-params.h
	mkdir -p $(CUR_BUILD)
	$< > $@

$(CUR_BUILD)/aggregated-params.h: tools/extract-sphincs-params.c $(HEADERS) $(CUR_BUILD)/params.txt
	mkdir -p $(CUR_BUILD)
	rm -f $@
	@set -eu; \
	param_ids=$$(cat $(CUR_BUILD)/params.txt | cut -d" " -f1); \
	for param_id in $${param_ids}; do \
		param=$$(grep ^$${param_id} $(CUR_BUILD)/params.txt | head -1 | cut -d" " -f2); \
		set -x; \
		$(CLANG) -g -O3 $< -o $(CUR_BUILD)/extract-params_$${param} \
			-DPARAMS_ID=$${param_id} -DPARAMS=$${param} \
			-I $(SPHINCS_PLUS_DIR) -I $(cur_dir); \
		$(CUR_BUILD)/extract-params_$${param} >> $@; \
		set +x; \
	done;

$(CUR_BUILD)/params.txt: $(TOP)/target/$(MODE)/generate-params-txt
	mkdir -p $(CUR_BUILD)
	$< > $@

fmt:
	$(CLANG_FORMAT) -i --style='{BasedOnStyle: google, SortIncludes: false}' *.c *.h tools/*.c utils/*.h

clean:
	rm -rf $(CUR_BUILD)

.PHONY: build clean fmt
