#include "params.h"

#include "hash.h"
#include "sha2.h"
#include "thash.h"

void init_hash_param(crypto_context *cctx) {
  /* winternitz parameter, */
  cctx->spx_wots_w = 16;

  /* for clarity */
  cctx->spx_addr_bytes = 32;

  /* wots parameters. */
  if (cctx->spx_wots_w == 256) {
    cctx->spx_wots_logw = 8;
    if (cctx->spx_n <= 1) {
      cctx->spx_wots_len2 = 1;
    } else if (cctx->spx_n <= 256) {
      cctx->spx_wots_len2 = 2;
    } else {
      ASSERT(false);
    }
  } else if (cctx->spx_wots_w == 16) {
    cctx->spx_wots_logw = 4;
    if (cctx->spx_n <= 8) {
      cctx->spx_wots_len2 = 2;
    } else if (cctx->spx_n <= 136) {
      cctx->spx_wots_len2 = 3;
    } else if (cctx->spx_n <= 256) {
      cctx->spx_wots_len2 = 4;
    } else {
      ASSERT(false);
    }
  } else {
    ASSERT(false);
  }

  cctx->spx_wots_len1 = (8 * cctx->spx_n / cctx->spx_wots_logw);

  cctx->spx_wots_len = (cctx->spx_wots_len1 + cctx->spx_wots_len2);
  cctx->spx_wots_bytes = (cctx->spx_wots_len * cctx->spx_n);
  cctx->spx_wots_pk_bytes = cctx->spx_wots_bytes;

  /* subtree size. */
  cctx->spx_tree_height = (cctx->spx_full_height / cctx->spx_d);

  /* fors parameters. */
  cctx->spx_fors_msg_bytes =
      ((cctx->spx_fors_height * cctx->spx_fors_trees + 7) / 8);
  cctx->spx_fors_bytes =
      ((cctx->spx_fors_height + 1) * cctx->spx_fors_trees * cctx->spx_n);
  cctx->spx_fors_pk_bytes = cctx->spx_n;

  /* resulting spx sizes. */
  cctx->spx_bytes =
      (cctx->spx_n + cctx->spx_fors_bytes + cctx->spx_d * cctx->spx_wots_bytes +
       cctx->spx_full_height * cctx->spx_n);
  cctx->spx_pk_bytes = (2 * cctx->spx_n);
  cctx->spx_sk_bytes = (2 * cctx->spx_n + cctx->spx_pk_bytes);

  cctx->crypto_seedbytes = 3 * cctx->spx_n;
}

void init_shake(crypto_context *cctx) {
  cctx->spx_offset_layer = 3;
  cctx->spx_offset_tree = 8;
  cctx->spx_offset_type = 19;
  cctx->spx_offset_kp_addr2 = 22;
  cctx->spx_offset_kp_addr1 = 23;
  cctx->spx_offset_chain_addr = 27;
  cctx->spx_offset_hash_addr = 31;
  cctx->spx_offset_tree_hgt = 27;
  cctx->spx_offset_tree_index = 28;

  init_hash_param(cctx);
}

void init_sha2(crypto_context *cctx) {
  cctx->spx_offset_layer = 0;
  cctx->spx_offset_tree = 1;
  cctx->spx_offset_type = 9;
  cctx->spx_offset_kp_addr2 = 12;
  cctx->spx_offset_kp_addr1 = 13;
  cctx->spx_offset_chain_addr = 17;
  cctx->spx_offset_hash_addr = 21;
  cctx->spx_offset_tree_hgt = 17;
  cctx->spx_offset_tree_index = 18;

  init_hash_param(cctx);
}

void init_haraka(crypto_context *cctx) {
  cctx->spx_offset_layer = 3;
  cctx->spx_offset_tree = 8;
  cctx->spx_offset_type = 19;
  cctx->spx_offset_kp_addr2 = 22;
  cctx->spx_offset_kp_addr1 = 23;
  cctx->spx_offset_chain_addr = 27;
  cctx->spx_offset_hash_addr = 31;
  cctx->spx_offset_tree_hgt = 27;
  cctx->spx_offset_tree_index = 28;

  init_hash_param(cctx);
}

void init_128s(crypto_context *cctx) {
  cctx->spx_n = 16;
  cctx->spx_full_height = 63;
  cctx->spx_d = 7;
  cctx->spx_fors_height = 12;
  cctx->spx_fors_trees = 14;
}

void init_128f(crypto_context *cctx) {
  cctx->spx_n = 16;
  cctx->spx_full_height = 66;
  cctx->spx_d = 22;
  cctx->spx_fors_height = 6;
  cctx->spx_fors_trees = 33;
}

void init_192s(crypto_context *cctx) {
  cctx->spx_n = 24;
  cctx->spx_full_height = 63;
  cctx->spx_d = 7;
  cctx->spx_fors_height = 14;
  cctx->spx_fors_trees = 17;
}

void init_192f(crypto_context *cctx) {
  cctx->spx_n = 24;
  cctx->spx_full_height = 66;
  cctx->spx_d = 22;
  cctx->spx_fors_height = 8;
  cctx->spx_fors_trees = 33;
}

void init_256s(crypto_context *cctx) {
  cctx->spx_n = 32;
  cctx->spx_full_height = 64;
  cctx->spx_d = 8;
  cctx->spx_fors_height = 14;
  cctx->spx_fors_trees = 22;
}

void init_256f(crypto_context *cctx) {
  cctx->spx_n = 32;
  cctx->spx_full_height = 68;
  cctx->spx_d = 17;
  cctx->spx_fors_height = 9;
  cctx->spx_fors_trees = 35;
}

void init_sha2_256(crypto_context *cctx) {
  cctx->spx_sha512 = 0;

  cctx->spx_shax_output_bytes = 32;
  cctx->spx_shax_block_bytes = 64;
  cctx->func_shax_inc_init = sha256_inc_init;
  cctx->func_shax_inc_blocks = sha256_inc_blocks;
  cctx->func_shax_inc_finalize = sha256_inc_finalize;
  cctx->func_shax = sha256;
  cctx->func_mgf1_x = mgf1_256;
}

void init_sha2_512(crypto_context *cctx) {
  cctx->spx_sha512 = 1;
  cctx->spx_shax_output_bytes = 64;
  cctx->spx_shax_block_bytes = 128;
  cctx->func_shax_inc_init = sha512_inc_init;
  cctx->func_shax_inc_blocks = sha512_inc_blocks;
  cctx->func_shax_inc_finalize = sha512_inc_finalize;
  cctx->func_shax = sha512;
  cctx->func_mgf1_x = mgf1_512;
}

#define GEN_INIT_HASH_FUNC(NAME, name, size, option, thash)            \
  int init_##name##_##size##option##_##thash(crypto_context *cctx) {   \
    if (CRYPTO_HASH_TYPE_##NAME == CRYPTO_HASH_TYPE_SHA2) {            \
      if (size > 128) {                                                \
        init_sha2_512(cctx);                                           \
      } else {                                                         \
        init_sha2_256(cctx);                                           \
      }                                                                \
    } else {                                                           \
      cctx->spx_sha512 = 0;                                            \
    }                                                                  \
    cctx->hash_type = CRYPTO_HASH_TYPE_##NAME;                         \
    init_##size##option(cctx);                                         \
    init_##name(cctx);                                                 \
    cctx->func_thash = thash_##name##_##thash;                         \
    cctx->func_init_hash_function = initialize_##name##_hash_function; \
    cctx->func_prf_addr = name##_prf_addr;                             \
    cctx->func_gen_msg_rand = gen_##name##_message_random;             \
    cctx->func_hash_msg = name##_hash_message;                         \
    return 0;                                                          \
  }

#define GEN_INIT_HASH_FUNC2(NAME, name)           \
  GEN_INIT_HASH_FUNC(NAME, name, 128, s, robust); \
  GEN_INIT_HASH_FUNC(NAME, name, 128, s, simple); \
  GEN_INIT_HASH_FUNC(NAME, name, 128, f, robust); \
  GEN_INIT_HASH_FUNC(NAME, name, 128, f, simple); \
  GEN_INIT_HASH_FUNC(NAME, name, 192, s, robust); \
  GEN_INIT_HASH_FUNC(NAME, name, 192, s, simple); \
  GEN_INIT_HASH_FUNC(NAME, name, 192, f, robust); \
  GEN_INIT_HASH_FUNC(NAME, name, 192, f, simple); \
  GEN_INIT_HASH_FUNC(NAME, name, 256, s, robust); \
  GEN_INIT_HASH_FUNC(NAME, name, 256, s, simple); \
  GEN_INIT_HASH_FUNC(NAME, name, 256, f, robust); \
  GEN_INIT_HASH_FUNC(NAME, name, 256, f, simple);

GEN_INIT_HASH_FUNC2(SHAKE, shake);
GEN_INIT_HASH_FUNC2(SHA2, sha2);
GEN_INIT_HASH_FUNC2(HARAKA, haraka);

#undef GEN_INIT_HASH_FUNC2
#undef GEN_INIT_HASH_FUNC

#define SWITCH_CASE_TYPE(NAME, name, size, OPTION, option, THASH, thash) \
  case CRYPTO_TYPE_##NAME##_##size##OPTION##_##THASH:                    \
    return init_##name##_##size##option##_##thash(cctx);

#define SWITCH_CASE_HASH_TYPE(NAME, name, size)             \
  SWITCH_CASE_TYPE(NAME, name, size, S, s, ROBUST, robust); \
  SWITCH_CASE_TYPE(NAME, name, size, S, s, SIMPLE, simple); \
  SWITCH_CASE_TYPE(NAME, name, size, F, f, ROBUST, robust); \
  SWITCH_CASE_TYPE(NAME, name, size, F, f, SIMPLE, simple);

#define SWITCH_CASE_HASH_TYPE2(NAME, name) \
  SWITCH_CASE_HASH_TYPE(NAME, name, 128);  \
  SWITCH_CASE_HASH_TYPE(NAME, name, 192);  \
  SWITCH_CASE_HASH_TYPE(NAME, name, 256);

int crypto_init_context(crypto_type type, crypto_context *cctx) {
  cctx->type = type;

  switch (type) {
    SWITCH_CASE_HASH_TYPE2(SHAKE, shake);
    SWITCH_CASE_HASH_TYPE2(SHA2, sha2);
    SWITCH_CASE_HASH_TYPE2(HARAKA, haraka);
    default:
      return 1;
  }
}

#undef SWITCH_CASE_HASH_TYPE2
#undef SWITCH_CASE_HASH_TYPE
#undef SWITCH_CASE_TYPE
