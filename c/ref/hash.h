#ifndef SPX_HASH_H
#define SPX_HASH_H

#include <stdint.h>

#include "params.h"

// #define initialize_hash_function SPX_NAMESPACE(initialize_hash_function)
// void initialize_hash_function(spx_ctx *ctx);

#define initialize_shake_hash_function \
  SPX_NAMESPACE(initialize_shake_hash_function)
void initialize_shake_hash_function(void *p_cctx, spx_ctx *ctx);

#define initialize_sha2_hash_function \
  SPX_NAMESPACE(initialize_sha2_hash_function)
void initialize_sha2_hash_function(void *p_cctx, spx_ctx *ctx);

#define initialize_haraka_hash_function \
  SPX_NAMESPACE(initialize_haraka_hash_function)
void initialize_haraka_hash_function(void *p_cctx, spx_ctx *ctx);

// #define prf_addr SPX_NAMESPACE(prf_addr)
// void prf_addr(unsigned char *out, const spx_ctx *ctx, const uint32_t
// addr[8]);

#define shake_prf_addr SPX_NAMESPACE(shake_prf_addr)
void shake_prf_addr(void *p_cctx, unsigned char *out, const spx_ctx *ctx,
                    const uint32_t addr[8]);

#define sha2_prf_addr SPX_NAMESPACE(prf_shake_addr)
void sha2_prf_addr(void *p_cctx, unsigned char *out, const spx_ctx *ctx,
                   const uint32_t addr[8]);

#define haraka_prf_addr SPX_NAMESPACE(haraka_prf_addr)
void haraka_prf_addr(void *p_cctx, unsigned char *out, const spx_ctx *ctx,
                     const uint32_t addr[8]);

// #define gen_message_random SPX_NAMESPACE(gen_message_random)
// void gen_message_random(unsigned char *R, const unsigned char *sk_prf,
//                         const unsigned char *optrand, const unsigned char *m,
//                         unsigned long long mlen, const spx_ctx *ctx);

#define gen_shake_message_random SPX_NAMESPACE(gen_shake_message_random)
void gen_shake_message_random(void *p_cctx, unsigned char *R,
                              const unsigned char *sk_prf,
                              const unsigned char *optrand,
                              const unsigned char *m, unsigned long long mlen,
                              const spx_ctx *ctx);

#define gen_sha2_message_random SPX_NAMESPACE(gen_sha2_message_random)
void gen_sha2_message_random(void *p_cctx, unsigned char *R,
                             const unsigned char *sk_prf,
                             const unsigned char *optrand,
                             const unsigned char *m, unsigned long long mlen,
                             const spx_ctx *ctx);

#define gen_haraka_message_random SPX_NAMESPACE(gen_haraka_message_random)
void gen_haraka_message_random(void *p_cctx, unsigned char *R,
                               const unsigned char *sk_prf,
                               const unsigned char *optrand,
                               const unsigned char *m, unsigned long long mlen,
                               const spx_ctx *ctx);

// #define hash_message SPX_NAMESPACE(hash_message)
// void hash_message(unsigned char *digest, uint64_t *tree, uint32_t *leaf_idx,
//                   const unsigned char *R, const unsigned char *pk,
//                   const unsigned char *m, unsigned long long mlen,
//                   const spx_ctx *ctx);

#define shake_hash_message SPX_NAMESPACE(shake_hash_message)
void shake_hash_message(void *p_cctx, unsigned char *digest, uint64_t *tree,
                        uint32_t *leaf_idx, const unsigned char *R,
                        const unsigned char *pk, const unsigned char *m,
                        unsigned long long mlen, const spx_ctx *ctx);

#define sha2_hash_message SPX_NAMESPACE(sha2_hash_message)
void sha2_hash_message(void *p_cctx, unsigned char *digest, uint64_t *tree,
                       uint32_t *leaf_idx, const unsigned char *R,
                       const unsigned char *pk, const unsigned char *m,
                       unsigned long long mlen, const spx_ctx *ctx);

#define haraka_hash_message SPX_NAMESPACE(haraka_hash_message)
void haraka_hash_message(void *p_cctx, unsigned char *digest, uint64_t *tree,
                         uint32_t *leaf_idx, const unsigned char *R,
                         const unsigned char *pk, const unsigned char *m,
                         unsigned long long mlen, const spx_ctx *ctx);

#endif
