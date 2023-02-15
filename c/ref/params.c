#include "params.h"

#include <stddef.h>

crypto_context g_context;

int init_shake_256f_robust() {
  g_context.type = CRYPTO_TYPE_SHAKE_256F_ROBUST;
  /* Hash output length in bytes. */
  g_context.spx_n = 32;
  /* height of the hypertree. */
  g_context.spx_full_height = 68;
  /* number of subtree layer. */
  g_context.spx_d = 17;
  /* fors tree dimensions. */
  g_context.spx_fors_height = 9;
  g_context.spx_fors_trees = 35;
  /* winternitz parameter, */
  g_context.spx_wots_w = 16;

  /* the hash function is defined by linking a different hash.c file, as opposed
     to setting a #define constant. */

  /* for clarity */
  g_context.spx_addr_bytes = 32;

  /* wots parameters. */
  g_context.spx_wots_logw = 4;

  g_context.spx_wots_len1 = (8 * g_context.spx_n / g_context.spx_wots_logw);

  g_context.spx_wots_len2 = 3;

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

  return 0;
}
