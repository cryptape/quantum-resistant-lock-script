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
	$(SPHINCS_PLUS_DIR)/fips202.h \
	$(SPHINCS_PLUS_DIR)/haraka.h \
	$(SPHINCS_PLUS_DIR)/sha2.h \
	$(LOCK_DIR)/ckb-sphincsplus.h \
	$(LOCK_DIR)/ckb-sphincsplus-common.h \
	$(wildcard $(LOCK_DIR)/utils/*.h)

COMPILING_COMMON_SOURCES = \
	$(SPHINCS_PLUS_DIR)/address.c \
	$(SPHINCS_PLUS_DIR)/merkle.c \
	$(SPHINCS_PLUS_DIR)/wots.c \
	$(SPHINCS_PLUS_DIR)/wotsx1.c \
	$(SPHINCS_PLUS_DIR)/utils.c \
	$(SPHINCS_PLUS_DIR)/utilsx1.c \
	$(SPHINCS_PLUS_DIR)/fors.c \
	$(SPHINCS_PLUS_DIR)/sign.c \
	$(LOCK_DIR)/ckb-sphincsplus.c

COMPILING_NATIVE_SOURCES = \
	$(COMPILING_COMMON_SOURCES) \
	$(SPHINCS_PLUS_DIR)/randombytes.c

COMPILING_SHAKE_SOURCES = \
	$(SPHINCS_PLUS_DIR)/fips202.c \
	$(SPHINCS_PLUS_DIR)/hash_shake.c \
	$(SPHINCS_PLUS_DIR)/thash_shake_$(THASH).c

COMPILING_HARAKA_SOURCES = \
	$(SPHINCS_PLUS_DIR)/haraka.c \
	$(SPHINCS_PLUS_DIR)/hash_haraka.c \
	$(SPHINCS_PLUS_DIR)/thash_haraka_$(THASH).c

COMPILING_SHA2_SOURCES = \
	$(SPHINCS_PLUS_DIR)/sha2.c \
	$(SPHINCS_PLUS_DIR)/hash_sha2.c \
	$(SPHINCS_PLUS_DIR)/thash_sha2_$(THASH).c

DETECTING_SOURCES = \
	$(COMPILING_NATIVE_SOURCES) \
	$(COMPILING_SHAKE_SOURCES) \
	$(COMPILING_HARAKA_SOURCES) \
	$(COMPILING_SHA2_SOURCES)

COMPILING_SOURCES_BY_PARAMS = $(COMPILING_COMMON_SOURCES)
ifneq (,$(findstring shake,$(PARAMS)))
	COMPILING_SOURCES_BY_PARAMS += \
		$(SPHINCS_PLUS_DIR)/fips202.c \
		$(SPHINCS_PLUS_DIR)/hash_shake.c \
		$(SPHINCS_PLUS_DIR)/thash_shake_$(THASH).c
endif
ifneq (,$(findstring haraka,$(PARAMS)))
	COMPILING_SOURCES_BY_PARAMS += \
		$(SPHINCS_PLUS_DIR)/haraka.c \
		$(SPHINCS_PLUS_DIR)/hash_haraka.c \
		$(SPHINCS_PLUS_DIR)/thash_haraka_$(THASH).c
endif
ifneq (,$(findstring sha2,$(PARAMS)))
	COMPILING_SOURCES_BY_PARAMS += \
		$(SPHINCS_PLUS_DIR)/sha2.c \
		$(SPHINCS_PLUS_DIR)/hash_sha2.c \
		$(SPHINCS_PLUS_DIR)/thash_sha2_$(THASH).c
endif
