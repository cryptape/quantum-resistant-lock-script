#include "params.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>

#include "thash.h"

crypto_context g_context;

void init_shake() {
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
      assert(false);
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
      assert(false);
    }
  } else {
    assert(false);
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

void init_shake_128s() {
  g_context.spx_n = 16;
  g_context.spx_full_height = 63;
  g_context.spx_d = 7;
  g_context.spx_fors_height = 12;
  g_context.spx_fors_trees = 14;
  init_shake();
}

void init_shake_128f() {
  g_context.spx_n = 16;
  g_context.spx_full_height = 66;
  g_context.spx_d = 22;
  g_context.spx_fors_height = 6;
  g_context.spx_fors_trees = 33;
  init_shake();
}

void init_shake_192s() {
  g_context.spx_n = 24;
  g_context.spx_full_height = 63;
  g_context.spx_d = 7;
  g_context.spx_fors_height = 14;
  g_context.spx_fors_trees = 17;
  init_shake();
}

void init_shake_192f() {
  g_context.spx_n = 24;
  g_context.spx_full_height = 66;
  g_context.spx_d = 22;
  g_context.spx_fors_height = 8;
  g_context.spx_fors_trees = 33;
  init_shake();
}

void init_shake_256s() {
  g_context.spx_n = 32;
  g_context.spx_full_height = 64;
  g_context.spx_d = 8;
  g_context.spx_fors_height = 14;
  g_context.spx_fors_trees = 22;
  init_shake();
}

void init_shake_256f() {
  g_context.spx_n = 32;
  g_context.spx_full_height = 68;
  g_context.spx_d = 17;
  g_context.spx_fors_height = 9;
  g_context.spx_fors_trees = 35;
  init_shake();
}

#define GEN_INIT_HASH_FUNC(name, size, option, thash) \
  int init_##name##_##size##option##_##thash() {      \
    init_##name##_##size##option();                   \
    g_context.func_thash = thash_##name##_##thash;    \
    return 0;                                         \
  }

#define GEN_INIT_SHAKE_FUNC2(size)            \
  GEN_INIT_HASH_FUNC(shake, size, s, robust); \
  GEN_INIT_HASH_FUNC(shake, size, s, simple); \
  GEN_INIT_HASH_FUNC(shake, size, f, robust); \
  GEN_INIT_HASH_FUNC(shake, size, f, simple);

GEN_INIT_SHAKE_FUNC2(128);
GEN_INIT_SHAKE_FUNC2(192);
GEN_INIT_SHAKE_FUNC2(256);

#undef GEN_INIT_SHAKE_FUNC2
#undef GEN_INIT_HASH_FUNC
