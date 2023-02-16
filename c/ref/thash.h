#ifndef SPX_THASH_H
#define SPX_THASH_H

#include <stdint.h>

#include "params.h"

#define thash_shake_robust SPX_NAMESPACE(thash_shake_robust)
void thash_shake_robust(unsigned char *out, const unsigned char *in,
                        unsigned int inblocks, const spx_ctx *ctx,
                        uint32_t addr[8]);

#define thash_shake_simple SPX_NAMESPACE(thash_shake_simple)
void thash_shake_simple(unsigned char *out, const unsigned char *in,
                        unsigned int inblocks, const spx_ctx *ctx,
                        uint32_t addr[8]);

#endif
