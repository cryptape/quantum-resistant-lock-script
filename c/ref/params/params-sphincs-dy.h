#ifndef _C_REF_PARAMS_PARAMS_SPHINCS_DY_H_
#define _C_REF_PARAMS_PARAMS_SPHINCS_DY_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "context.h"

typedef enum {
  // SHAKE
  CRYPTO_TYPE_SHAKE_128S_ROBUST = 1,
  CRYPTO_TYPE_SHAKE_128S_SIMPLE,
  CRYPTO_TYPE_SHAKE_128F_ROBUST,
  CRYPTO_TYPE_SHAKE_128F_SIMPLE,

  CRYPTO_TYPE_SHAKE_192S_ROBUST,
  CRYPTO_TYPE_SHAKE_192S_SIMPLE,
  CRYPTO_TYPE_SHAKE_192F_ROBUST,
  CRYPTO_TYPE_SHAKE_192F_SIMPLE,

  CRYPTO_TYPE_SHAKE_256S_ROBUST,
  CRYPTO_TYPE_SHAKE_256S_SIMPLE,
  CRYPTO_TYPE_SHAKE_256F_ROBUST,
  CRYPTO_TYPE_SHAKE_256F_SIMPLE,

  // SHA2
  CRYPTO_TYPE_SHA2_128S_ROBUST,
  CRYPTO_TYPE_SHA2_128S_SIMPLE,
  CRYPTO_TYPE_SHA2_128F_ROBUST,
  CRYPTO_TYPE_SHA2_128F_SIMPLE,

  CRYPTO_TYPE_SHA2_192S_ROBUST,
  CRYPTO_TYPE_SHA2_192S_SIMPLE,
  CRYPTO_TYPE_SHA2_192F_ROBUST,
  CRYPTO_TYPE_SHA2_192F_SIMPLE,

  CRYPTO_TYPE_SHA2_256S_ROBUST,
  CRYPTO_TYPE_SHA2_256S_SIMPLE,
  CRYPTO_TYPE_SHA2_256F_ROBUST,
  CRYPTO_TYPE_SHA2_256F_SIMPLE,

  // HARAKA
  CRYPTO_TYPE_HARAKA_128S_ROBUST,
  CRYPTO_TYPE_HARAKA_128S_SIMPLE,
  CRYPTO_TYPE_HARAKA_128F_ROBUST,
  CRYPTO_TYPE_HARAKA_128F_SIMPLE,

  CRYPTO_TYPE_HARAKA_192S_ROBUST,
  CRYPTO_TYPE_HARAKA_192S_SIMPLE,
  CRYPTO_TYPE_HARAKA_192F_ROBUST,
  CRYPTO_TYPE_HARAKA_192F_SIMPLE,

  CRYPTO_TYPE_HARAKA_256S_ROBUST,
  CRYPTO_TYPE_HARAKA_256S_SIMPLE,
  CRYPTO_TYPE_HARAKA_256F_ROBUST,
  CRYPTO_TYPE_HARAKA_256F_SIMPLE,

} crypto_type;

typedef enum {
  CRYPTO_HASH_TYPE_SHAKE,
  CRYPTO_HASH_TYPE_SHA2,
  CRYPTO_HASH_TYPE_HARAKA,
} crypto_hash_type;

typedef void (*func_spx_thash)(void *p_cctx, unsigned char *out,
                               const unsigned char *in, unsigned int inblocks,
                               const spx_ctx *ctx, uint32_t addr[8]);
typedef void (*func_spx_initialize_hash_function)(void *p_cctx, spx_ctx *ctx);
typedef void (*func_spx_prf_addr)(void *p_cctx, unsigned char *out,
                                  const spx_ctx *ctx, const uint32_t addr[8]);
typedef void (*func_spx_gen_msg_rand)(void *p_cctx, unsigned char *R,
                                      const unsigned char *sk_prf,
                                      const unsigned char *optrand,
                                      const unsigned char *m,
                                      unsigned long long mlen,
                                      const spx_ctx *ctx);
typedef void (*func_spx_hash_message)(
    void *p_cctx, unsigned char *digest, uint64_t *tree, uint32_t *leaf_idx,
    const unsigned char *R, const unsigned char *pk, const unsigned char *m,
    unsigned long long mlen, const spx_ctx *ctx);

typedef void (*func_spx_shax_inc_init)(uint8_t *state);
typedef void (*func_spx_shax_inc_blocks)(uint8_t *state, const uint8_t *in,
                                         size_t inblocks);
typedef void (*func_spx_shax_inc_finalize)(uint8_t *out, uint8_t *state,
                                           const uint8_t *in, size_t inlen);
typedef void (*func_spx_shax)(uint8_t *out, const uint8_t *in, size_t inlen);
typedef void (*func_spx_mgf1_x)(unsigned char *out, unsigned long outlen,
                                const unsigned char *in, unsigned long inlen);

typedef struct {
  crypto_type type;
  crypto_hash_type hash_type;

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

  // sha2 only
  size_t spx_sha512;
  size_t spx_shax_output_bytes;
  size_t spx_shax_block_bytes;
  func_spx_shax_inc_init func_shax_inc_init;
  func_spx_shax_inc_blocks func_shax_inc_blocks;
  func_spx_shax_inc_finalize func_shax_inc_finalize;
  func_spx_shax func_shax;
  func_spx_mgf1_x func_mgf1_x;

  size_t spx_offset_layer;
  size_t spx_offset_tree;
  size_t spx_offset_type;
  size_t spx_offset_kp_addr2;
  size_t spx_offset_kp_addr1;
  size_t spx_offset_chain_addr;
  size_t spx_offset_hash_addr;
  size_t spx_offset_tree_hgt;
  size_t spx_offset_tree_index;

  size_t crypto_seedbytes;

  func_spx_thash func_thash;
  func_spx_initialize_hash_function func_init_hash_function;
  func_spx_prf_addr func_prf_addr;
  func_spx_gen_msg_rand func_gen_msg_rand;
  func_spx_hash_message func_hash_msg;

} crypto_context;

#define GEN_INIT_HASH_FUNC(name, size, option, thash) \
  int init_##name##_##size##option##_##thash(crypto_context *ctx);

#define GEN_INIT_HASH_T_FUNC(name, size)     \
  GEN_INIT_HASH_FUNC(name, size, s, robust); \
  GEN_INIT_HASH_FUNC(name, size, f, robust); \
  GEN_INIT_HASH_FUNC(name, size, s, simple); \
  GEN_INIT_HASH_FUNC(name, size, f, simple);

#define GEN_INIT_HASH_T_FUNC2(name) \
  GEN_INIT_HASH_T_FUNC(name, 128);  \
  GEN_INIT_HASH_T_FUNC(name, 192);  \
  GEN_INIT_HASH_T_FUNC(name, 256);

GEN_INIT_HASH_T_FUNC2(shake);
GEN_INIT_HASH_T_FUNC2(sha2);
GEN_INIT_HASH_T_FUNC2(haraka);

#undef GEN_INIT_HASH_T_FUNC2
#undef GEN_INIT_HASH_T_FUNC
#undef GEN_INIT_HASH_FUNC

#define SPX_N cctx->spx_n
#define SPX_FULL_HEIGHT cctx->spx_full_height
#define SPX_D cctx->spx_d
#define SPX_FORS_HEIGHT cctx->spx_fors_height
#define SPX_FORS_TREES cctx->spx_fors_trees
#define SPX_WOTS_W cctx->spx_wots_w
#define SPX_ADDR_BYTES cctx->spx_addr_bytes
#define SPX_WOTS_LOGW cctx->spx_wots_logw
#define SPX_WOTS_LEN1 cctx->spx_wots_len1
#define SPX_WOTS_LEN2 cctx->spx_wots_len2
#define SPX_WOTS_LEN cctx->spx_wots_len
#define SPX_WOTS_BYTES cctx->spx_wots_bytes
#define SPX_WOTS_PK_BYTES cctx->spx_wots_pk_bytes
#define SPX_TREE_HEIGHT cctx->spx_tree_height
#define SPX_FORS_MSG_BYTES cctx->spx_fors_msg_bytes
#define SPX_FORS_BYTES cctx->spx_fors_bytes
#define SPX_FORS_PK_BYTES cctx->spx_fors_pk_bytes
#define SPX_BYTES cctx->spx_bytes
#define SPX_PK_BYTES cctx->spx_pk_bytes
#define SPX_SK_BYTES cctx->spx_sk_bytes

#define SPX_SHA512 cctx->spx_sha512

#define SPX_OFFSET_LAYER cctx->spx_offset_layer
#define SPX_OFFSET_TREE cctx->spx_offset_tree
#define SPX_OFFSET_TYPE cctx->spx_offset_type
#define SPX_OFFSET_KP_ADDR2 cctx->spx_offset_kp_addr2
#define SPX_OFFSET_KP_ADDR1 cctx->spx_offset_kp_addr1
#define SPX_OFFSET_CHAIN_ADDR cctx->spx_offset_chain_addr
#define SPX_OFFSET_HASH_ADDR cctx->spx_offset_hash_addr
#define SPX_OFFSET_TREE_HGT cctx->spx_offset_tree_hgt
#define SPX_OFFSET_TREE_INDEX cctx->spx_offset_tree_index

#define SPX_SHAX_OUTPUT_BYTES cctx->spx_shax_output_bytes
#define SPX_SHAX_BLOCK_BYTES cctx->spx_shax_block_bytes
#define shaX_inc_init cctx->func_shax_inc_init
#define shaX_inc_blocks cctx->func_shax_inc_blocks
#define shaX_inc_finalize cctx->func_shax_inc_finalize
#define shaX cctx->func_shax
#define mgf1_X cctx->func_mgf1_x

#define SPX_NAMESPACE(s) SPX_##s

#define thash cctx->func_thash
#define initialize_hash_function cctx->func_init_hash_function
#define prf_addr cctx->func_prf_addr
#define gen_message_random cctx->func_gen_msg_rand
#define hash_message cctx->func_hash_msg

#ifndef ASSERT
#define ASSERT(c)                                \
  if (!(c)) {                                    \
    printf("Assert: %s:%d", __FILE__, __LINE__); \
    ((void)0);                                   \
  }
#endif  // ASSERT

#endif  // _C_REF_PARAMS_PARAMS_SPHINCS_DY_H_
