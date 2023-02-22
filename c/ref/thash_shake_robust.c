#include <stdint.h>
#include <string.h>

#include "address.h"
#include "fips202.h"
#include "params.h"
#include "thash.h"
#include "utils.h"

/**
 * Takes an array of inblocks concatenated arrays of SPX_N bytes.
 */
void thash_shake_robust(void *p_cctx, unsigned char *out,
                        const unsigned char *in, unsigned int inblocks,
                        const spx_ctx *ctx, uint32_t addr[8]) {
  crypto_context *cctx = (crypto_context *)p_cctx;
  SPX_VLA(uint8_t, buf, SPX_N + SPX_ADDR_BYTES + inblocks * SPX_N);
  SPX_VLA(uint8_t, bitmask, inblocks * SPX_N);
  unsigned int i;

  memcpy(buf, ctx->pub_seed, SPX_N);
  memcpy(buf + SPX_N, addr, SPX_ADDR_BYTES);

  shake256(bitmask, inblocks * SPX_N, buf, SPX_N + SPX_ADDR_BYTES);

  for (i = 0; i < inblocks * SPX_N; i++) {
    buf[SPX_N + SPX_ADDR_BYTES + i] = in[i] ^ bitmask[i];
  }

  shake256(out, SPX_N, buf, SPX_N + SPX_ADDR_BYTES + inblocks * SPX_N);
}
