#include <stdint.h>
#include <string.h>

#include "address.h"
#include "params.h"
#include "sha2.h"
#include "thash.h"
#include "utils.h"

static void thash_sha2_512_simple(crypto_context *cctx, unsigned char *out,
                                  const unsigned char *in,
                                  unsigned int inblocks, const spx_ctx *ctx,
                                  uint32_t addr[8]);

/**
 * Takes an array of inblocks concatenated arrays of SPX_N bytes.
 */
void thash_sha2_simple(void *p_cctx, unsigned char *out,
                       const unsigned char *in, unsigned int inblocks,
                       const spx_ctx *ctx, uint32_t addr[8]) {
  crypto_context *cctx = (crypto_context *)p_cctx;
  if (SPX_SHA512 == 1) {
    if (inblocks > 1) {
      thash_sha2_512_simple(cctx, out, in, inblocks, ctx, addr);
      return;
    }
  }

  unsigned char outbuf[SPX_SHA256_OUTPUT_BYTES];
  uint8_t sha2_state[40];
  SPX_VLA(uint8_t, buf, SPX_SHA256_ADDR_BYTES + inblocks * SPX_N);

  /* Retrieve precomputed state containing pub_seed */
  memcpy(sha2_state, ctx->state_seeded, 40 * sizeof(uint8_t));

  memcpy(buf, addr, SPX_SHA256_ADDR_BYTES);
  memcpy(buf + SPX_SHA256_ADDR_BYTES, in, inblocks * SPX_N);

  sha256_inc_finalize(outbuf, sha2_state, buf,
                      SPX_SHA256_ADDR_BYTES + inblocks * SPX_N);
  memcpy(out, outbuf, SPX_N);
}

static void thash_sha2_512_simple(crypto_context *cctx, unsigned char *out,
                                  const unsigned char *in,
                                  unsigned int inblocks, const spx_ctx *ctx,
                                  uint32_t addr[8]) {
  unsigned char outbuf[SPX_SHA512_OUTPUT_BYTES];
  uint8_t sha2_state[72];
  SPX_VLA(uint8_t, buf, SPX_SHA256_ADDR_BYTES + inblocks * SPX_N);

  /* Retrieve precomputed state containing pub_seed */
  memcpy(sha2_state, ctx->state_seeded_512, 72 * sizeof(uint8_t));

  memcpy(buf, addr, SPX_SHA256_ADDR_BYTES);
  memcpy(buf + SPX_SHA256_ADDR_BYTES, in, inblocks * SPX_N);

  sha512_inc_finalize(outbuf, sha2_state, buf,
                      SPX_SHA256_ADDR_BYTES + inblocks * SPX_N);
  memcpy(out, outbuf, SPX_N);
}
