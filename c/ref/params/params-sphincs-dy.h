#ifndef _C_REF_PARAMS_PARAMS_SPHINCS_DY_H_
#define _C_REF_PARAMS_PARAMS_SPHINCS_DY_H_

#include <stddef.h>
#include <stdint.h>

#include "context.h"

typedef enum {
  CRYPTO_TYPE_SHAKE_256F_ROBUST,
  CRYPTO_TYPE_SHAKE_256F_SIMPLE,
} crypto_type;

typedef void (*func_spx_thash)(unsigned char *out, const unsigned char *in,
                               unsigned int inblocks, const spx_ctx *ctx,
                               uint32_t addr[8]);

typedef struct {
  crypto_type type;

  size_t spx_n;
  size_t spx_full_height;
  size_t spx_d;
  size_t spx_fors_height;
  size_t spx_fors_trees;
  size_t spx_wots_w;
  size_t spx_addr_bytes;
  size_t spx_wots_logw;
  size_t spx_wots_len1;
  size_t spx_wots_len2;
  size_t spx_wots_len;
  size_t spx_wots_bytes;
  size_t spx_wots_pk_bytes;
  size_t spx_tree_height;
  size_t spx_fors_msg_bytes;
  size_t spx_fors_bytes;
  size_t spx_fors_pk_bytes;
  size_t spx_bytes;
  size_t spx_pk_bytes;
  size_t spx_sk_bytes;

  size_t crypto_seedbytes;

  func_spx_thash func_thash;

} crypto_context;

extern crypto_context g_context;

int init_shake_256f_robust();
int init_shake_256f_simple();

#define SPX_N g_context.spx_n
#define SPX_FULL_HEIGHT g_context.spx_full_height
#define SPX_D g_context.spx_d
#define SPX_FORS_HEIGHT g_context.spx_fors_height
#define SPX_FORS_TREES g_context.spx_fors_trees
#define SPX_WOTS_W g_context.spx_wots_w
#define SPX_ADDR_BYTES g_context.spx_addr_bytes
#define SPX_WOTS_LOGW g_context.spx_wots_logw
#define SPX_WOTS_LEN1 g_context.spx_wots_len1
#define SPX_WOTS_LEN2 g_context.spx_wots_len2
#define SPX_WOTS_LEN g_context.spx_wots_len
#define SPX_WOTS_BYTES g_context.spx_wots_bytes
#define SPX_WOTS_PK_BYTES g_context.spx_wots_pk_bytes
#define SPX_TREE_HEIGHT g_context.spx_tree_height
#define SPX_FORS_MSG_BYTES g_context.spx_fors_msg_bytes
#define SPX_FORS_BYTES g_context.spx_fors_bytes
#define SPX_FORS_PK_BYTES g_context.spx_fors_pk_bytes
#define SPX_BYTES g_context.spx_bytes
#define SPX_PK_BYTES g_context.spx_pk_bytes
#define SPX_SK_BYTES g_context.spx_sk_bytes

#define SPX_NAMESPACE(s) SPX_##s

#include "../shake_offsets.h"

#define thash g_context.func_thash

#endif  // _C_REF_PARAMS_PARAMS_SPHINCS_DY_H_
