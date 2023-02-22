#ifndef SPX_THASH_H
#define SPX_THASH_H

#include <stdint.h>

#include "params.h"

#define thash_shake_robust SPX_NAMESPACE(thash_shake_robust)
void thash_shake_robust(void *p_cctx, unsigned char *out,
                        const unsigned char *in, unsigned int inblocks,
                        const spx_ctx *ctx, uint32_t addr[8]);

#define thash_shake_simple SPX_NAMESPACE(thash_shake_simple)
void thash_shake_simple(void *p_cctx, unsigned char *out,
                        const unsigned char *in, unsigned int inblocks,
                        const spx_ctx *ctx, uint32_t addr[8]);

#define thash_sha2_robust SPX_NAMESPACE(thash_sha2_robust)
void thash_sha2_robust(void *p_cctx, unsigned char *out,
                       const unsigned char *in, unsigned int inblocks,
                       const spx_ctx *ctx, uint32_t addr[8]);

#define thash_sha2_simple SPX_NAMESPACE(thash_sha2_simple)
void thash_sha2_simple(void *p_cctx, unsigned char *out,
                       const unsigned char *in, unsigned int inblocks,
                       const spx_ctx *ctx, uint32_t addr[8]);

#define thash_haraka_robust SPX_NAMESPACE(thash_haraka_robust)
void thash_haraka_robust(void *p_cctx, unsigned char *out,
                         const unsigned char *in, unsigned int inblocks,
                         const spx_ctx *ctx, uint32_t addr[8]);

#define thash_haraka_simple SPX_NAMESPACE(thash_haraka_simple)
void thash_haraka_simple(void *p_cctx, unsigned char *out,
                         const unsigned char *in, unsigned int inblocks,
                         const spx_ctx *ctx, uint32_t addr[8]);

#endif
