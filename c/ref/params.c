#include "params.h"

#include <stdbool.h>
#include <stddef.h>

#include "hash.h"
#include "sha2.h"
#include "thash.h"

crypto_context g_context;

void init_hash_param() {
  /* winternitz parameter, */
  g_context.spx_wots_w = 16;

  /* for clarity */
  g_context.spx_addr_bytes = 32;

  /* wots parameters. */
  if (g_context.spx_wots_w == 256) {
    g_context.spx_wots_logw = 8;
    if (g_context.spx_n <= 1) {
      g_context.spx_wots_len2 = 1;
    } else if (g_context.spx_n <= 256) {
      g_context.spx_wots_len2 = 2;
    } else {
      ASSERT(false);
    }
  } else if (g_context.spx_wots_w == 16) {
    g_context.spx_wots_logw = 4;
    if (g_context.spx_n <= 8) {
      g_context.spx_wots_len2 = 2;
    } else if (g_context.spx_n <= 136) {
      g_context.spx_wots_len2 = 3;
    } else if (g_context.spx_n <= 256) {
      g_context.spx_wots_len2 = 4;
    } else {
      ASSERT(false);
    }
  } else {
    ASSERT(false);
  }

  g_context.spx_wots_len1 = (8 * g_context.spx_n / g_context.spx_wots_logw);

  g_context.spx_wots_len = (g_context.spx_wots_len1 + g_context.spx_wots_len2);
  g_context.spx_wots_bytes = (g_context.spx_wots_len * g_context.spx_n);
  g_context.spx_wots_pk_bytes = g_context.spx_wots_bytes;

  /* subtree size. */
  g_context.spx_tree_height = (g_context.spx_full_height / g_context.spx_d);

  /* fors parameters. */
  g_context.spx_fors_msg_bytes =
      ((g_context.spx_fors_height * g_context.spx_fors_trees + 7) / 8);
  g_context.spx_fors_bytes = ((g_context.spx_fors_height + 1) *
                              g_context.spx_fors_trees * g_context.spx_n);
  g_context.spx_fors_pk_bytes = g_context.spx_n;

  /* resulting spx sizes. */
  g_context.spx_bytes = (g_context.spx_n + g_context.spx_fors_bytes +
                         g_context.spx_d * g_context.spx_wots_bytes +
                         g_context.spx_full_height * g_context.spx_n);
  g_context.spx_pk_bytes = (2 * g_context.spx_n);
  g_context.spx_sk_bytes = (2 * g_context.spx_n + g_context.spx_pk_bytes);

  g_context.crypto_seedbytes = 3 * g_context.spx_n;
}

void init_shake() {
  g_context.spx_offset_layer = 3;
  g_context.spx_offset_tree = 8;
  g_context.spx_offset_type = 19;
  g_context.spx_offset_kp_addr2 = 22;
  g_context.spx_offset_kp_addr1 = 23;
  g_context.spx_offset_chain_addr = 27;
  g_context.spx_offset_hash_addr = 31;
  g_context.spx_offset_tree_hgt = 27;
  g_context.spx_offset_tree_index = 28;

  init_hash_param();
}

void init_sha2() {
  g_context.spx_offset_layer = 0;
  g_context.spx_offset_tree = 1;
  g_context.spx_offset_type = 9;
  g_context.spx_offset_kp_addr2 = 12;
  g_context.spx_offset_kp_addr1 = 13;
  g_context.spx_offset_chain_addr = 17;
  g_context.spx_offset_hash_addr = 21;
  g_context.spx_offset_tree_hgt = 17;
  g_context.spx_offset_tree_index = 18;

  init_hash_param();
}

void init_haraka() {
  g_context.spx_offset_layer = 3;
  g_context.spx_offset_tree = 8;
  g_context.spx_offset_type = 19;
  g_context.spx_offset_kp_addr2 = 22;
  g_context.spx_offset_kp_addr1 = 23;
  g_context.spx_offset_chain_addr = 27;
  g_context.spx_offset_hash_addr = 31;
  g_context.spx_offset_tree_hgt = 27;
  g_context.spx_offset_tree_index = 28;

  init_hash_param();
}

void init_128s() {
  g_context.spx_n = 16;
  g_context.spx_full_height = 63;
  g_context.spx_d = 7;
  g_context.spx_fors_height = 12;
  g_context.spx_fors_trees = 14;
}

void init_128f() {
  g_context.spx_n = 16;
  g_context.spx_full_height = 66;
  g_context.spx_d = 22;
  g_context.spx_fors_height = 6;
  g_context.spx_fors_trees = 33;
}

void init_192s() {
  g_context.spx_n = 24;
  g_context.spx_full_height = 63;
  g_context.spx_d = 7;
  g_context.spx_fors_height = 14;
  g_context.spx_fors_trees = 17;
}

void init_192f() {
  g_context.spx_n = 24;
  g_context.spx_full_height = 66;
  g_context.spx_d = 22;
  g_context.spx_fors_height = 8;
  g_context.spx_fors_trees = 33;
}

void init_256s() {
  g_context.spx_n = 32;
  g_context.spx_full_height = 64;
  g_context.spx_d = 8;
  g_context.spx_fors_height = 14;
  g_context.spx_fors_trees = 22;
}

void init_256f() {
  g_context.spx_n = 32;
  g_context.spx_full_height = 68;
  g_context.spx_d = 17;
  g_context.spx_fors_height = 9;
  g_context.spx_fors_trees = 35;
}

void init_sha2_256() {
  g_context.spx_sha512 = 0;

  g_context.spx_shax_output_bytes = 32;
  g_context.spx_shax_block_bytes = 64;
  g_context.func_shax_inc_init = sha256_inc_init;
  g_context.func_shax_inc_blocks = sha256_inc_blocks;
  g_context.func_shax_inc_finalize = sha256_inc_finalize;
  g_context.func_shax = sha256;
  g_context.func_mgf1_x = mgf1_256;
}

void init_sha2_512() {
  g_context.spx_sha512 = 1;
  g_context.spx_shax_output_bytes = 64;
  g_context.spx_shax_block_bytes = 128;
  g_context.func_shax_inc_init = sha512_inc_init;
  g_context.func_shax_inc_blocks = sha512_inc_blocks;
  g_context.func_shax_inc_finalize = sha512_inc_finalize;
  g_context.func_shax = sha512;
  g_context.func_mgf1_x = mgf1_512;
}

#define GEN_INIT_HASH_FUNC(NAME, name, size, option, thash)                \
  int init_##name##_##size##option##_##thash() {                           \
    if (CRYPTO_HASH_TYPE_##NAME == CRYPTO_HASH_TYPE_SHA2) {                \
      if (size > 128) {                                                    \
        init_sha2_512();                                                   \
      } else {                                                             \
        init_sha2_256();                                                   \
      }                                                                    \
    } else {                                                               \
      g_context.spx_sha512 = 0;                                            \
    }                                                                      \
    g_context.hash_type = CRYPTO_HASH_TYPE_##NAME;                         \
    init_##size##option();                                                 \
    init_##name();                                                         \
    g_context.func_thash = thash_##name##_##thash;                         \
    g_context.func_init_hash_function = initialize_##name##_hash_function; \
    g_context.func_prf_addr = name##_prf_addr;                             \
    g_context.func_gen_msg_rand = gen_##name##_message_random;             \
    g_context.func_hash_msg = name##_hash_message;                         \
    return 0;                                                              \
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
    return init_##name##_##size##option##_##thash();

#define SWITCH_CASE_HASH_TYPE(NAME, name, size)             \
  SWITCH_CASE_TYPE(NAME, name, size, S, s, ROBUST, robust); \
  SWITCH_CASE_TYPE(NAME, name, size, S, s, SIMPLE, simple); \
  SWITCH_CASE_TYPE(NAME, name, size, F, f, ROBUST, robust); \
  SWITCH_CASE_TYPE(NAME, name, size, F, f, SIMPLE, simple);

#define SWITCH_CASE_HASH_TYPE2(NAME, name) \
  SWITCH_CASE_HASH_TYPE(NAME, name, 128);  \
  SWITCH_CASE_HASH_TYPE(NAME, name, 192);  \
  SWITCH_CASE_HASH_TYPE(NAME, name, 256);

int crypto_init_context(crypto_type type) {
  g_context.type = type;

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

void memory_dump(void *ptr, int len) {
  int i;
  printf("%p\n", ptr);
  for (i = 0; i < len; i++) {
    if (i % 8 == 0 && i != 0) printf(" ");
    if (i % 16 == 0 && i != 0) printf("\n");
    printf("%02x ", *((uint8_t *)ptr + i));
  }
  printf("\n");
}
