# We cannot use $(shell pwd), which will return unix path format on Windows,
# making it hard to use.
cur_dir = $(dir $(abspath $(firstword $(MAKEFILE_LIST))))

TOP := $(cur_dir)
# RUSTFLAGS that are likely to be tweaked by developers. For example,
# while we enable debug logs by default here, some might want to strip them
# for minimal code size / consumed cycles.
CUSTOM_RUSTFLAGS := -C debug-assertions
# RUSTFLAGS that are less likely to be tweaked by developers. Most likely
# one would want to keep the default values here.
FULL_RUSTFLAGS := -C target-feature=+zba,+zbb,+zbc,+zbs,-a $(CUSTOM_RUSTFLAGS)
# Additional cargo args to append here. For example, one can use
# make test CARGO_ARGS="-- --nocapture" so as to inspect data emitted to
# stdout in unit tests
CARGO_ARGS :=
MODE := release
# Tweak this to change the clang version to use for building C code. By default
# we use a bash script with somes heuristics to find clang in current system.
CLANG := $(shell $(TOP)/scripts/find_clang)
AR := $(subst clang,llvm-ar,$(CLANG))
OBJCOPY := $(subst clang,llvm-objcopy,$(CLANG))
# When this is set to some value, the generated binaries will be copied over
BUILD_DIR :=
# Generated binaries to copy. By convention, a Rust crate's directory name will
# likely match the crate name, which is also the name of the final binary.
# However if this is not the case, you can tweak this variable. As the name hints,
# more than one binary is supported here.
BINARIES := $(notdir $(shell pwd))

C_DIR := $(TOP)/contracts/c-sphincs-all-in-one-lock
C_BUILD_DIR := $(C_DIR)/build

ifeq (release,$(MODE))
	MODE_ARGS := --release
endif

default: build test

build: src/generated/sizes.rs src/generated/offsets.rs src/generated/params.rs
	RUSTFLAGS="$(FULL_RUSTFLAGS)" TARGET_CC="$(CLANG)" TARGET_AR="$(AR)" \
		cargo build --target=riscv64imac-unknown-none-elf $(MODE_ARGS) $(CARGO_ARGS)
	mkdir -p build
	@set -eu; \
	if [ "x$(BUILD_DIR)" != "x" ]; then \
		for binary in $(BINARIES); do \
			echo "Copying binary $$binary to build directory"; \
			cp $(TOP)/target/riscv64imac-unknown-none-elf/$(MODE)/$$binary build/$${binary}_root.debug; \
			$(OBJCOPY) --strip-debug --strip-all build/$${binary}_root.debug build/$${binary}_root.stripped; \
			$(TOP)/target/$(MODE)/script-merge-tool --prefix CKB_ merge \
				--root-debug build/$${binary}_root.debug \
				--root-actual build/$${binary}_root.debug \
				--leaves $(C_BUILD_DIR)/leaves_debug \
				--output build/$${binary}.debug \
				--merge; \
			$(TOP)/target/$(MODE)/script-merge-tool --prefix CKB_ merge \
				--root-debug build/$${binary}_root.debug \
				--root-actual build/$${binary}_root.stripped \
				--leaves $(C_BUILD_DIR)/leaves_stripped \
				--output build/$${binary} \
				--merge; \
			cp build/$${binary}.debug $(TOP)/$(BUILD_DIR)/$${binary}.debug; \
			cp build/$${binary} $(TOP)/$(BUILD_DIR)/$${binary}; \
		done \
	fi

src/generated/sizes.rs: $(C_BUILD_DIR)/aggregated-params.h
	awk '{print "pub const", $$2, ": usize =", $$3, ";"}' $< | rustfmt > $@

src/generated/offsets.rs: $(TOP)/target/$(MODE)/script-merge-tool $(C_BUILD_DIR)/leaf.complete
	$< --prefix CKB_ generate \
		--leaves $(C_BUILD_DIR)/leaves_stripped \
		--language rust \
		--output $@
	rustfmt $@

src/generated/params.rs: $(TOP)/target/$(MODE)/generate-rust-params
	$< > $@
	rustfmt $@

# test, check, clippy and fmt here are provided for completeness,
# there is nothing wrong invoking cargo directly instead of make.
test:
	cargo test $(CARGO_ARGS)

check:
	cargo check $(CARGO_ARGS)

clippy:
	cargo clippy $(CARGO_ARGS)

fmt:
	cargo fmt $(CARGO_ARGS)

# Arbitrary cargo command is supported here. For example:
#
# make cargo CARGO_CMD=expand CARGO_ARGS="--ugly"
# 
# Invokes:
# cargo expand --ugly
CARGO_CMD :=
cargo:
	cargo $(CARGO_CMD) $(CARGO_ARGS)

clean:
	cargo clean

prepare:
	rustup target add riscv64imac-unknown-none-elf

.PHONY: build test check clippy fmt cargo clean prepare
