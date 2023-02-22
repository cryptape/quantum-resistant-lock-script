

#include "ckb-sphincsplus.h"

#include <stdint.h>

#include "address.h"
#include "api.h"
#include "context.h"
#include "fors.h"
#include "params.h"
#include "thash.h"
#include "utils.h"
#include "wotsx1.h"

// #include "ckb_vm_dbg.h"

enum SphincsPlusError {
  SphincsPlusError_Params = 200,
  SphincsPlusError_Verify,
  SphincsPlusError_Verify_MsgLen,
  SphincsPlusError_Verify_MsgCmp,
};

#ifndef CKB_VM

#include <stdlib.h>

crypto_context *sphincs_plus_new_context(crypto_type type) {
  crypto_context *cctx = (crypto_context *)malloc(sizeof(crypto_context));
  int err = crypto_init_context(type, cctx);
  ASSERT(err == 0);
  return cctx;
}

void sphincs_plus_del_context(crypto_context *cctx) { free(cctx); }

#endif  // CKB_VM

int sphincs_plus_init_context(crypto_type type, crypto_context *cctx) {
  memset(cctx, 0, sizeof(crypto_context));
  return crypto_init_context(type, cctx);
}

uint32_t sphincs_plus_get_pk_size(crypto_context *cctx) {
  return cctx->spx_pk_bytes;
}

uint32_t sphincs_plus_get_sk_size(crypto_context *cctx) {
  return cctx->spx_sk_bytes;
}

uint32_t sphincs_plus_get_sign_size(crypto_context *cctx) {
  return cctx->spx_bytes + SPX_MLEN;
}

#ifndef CKB_VM

int sphincs_plus_generate_keypair(crypto_context *cctx, uint8_t *pk,
                                  uint8_t *sk) {
  return crypto_sign_keypair(cctx, pk, sk);
}

int sphincs_plus_sign(crypto_context *cctx, uint8_t *message, uint8_t *sk,
                      uint8_t *out_sign) {
  unsigned long long out_sign_len = sphincs_plus_get_sign_size(cctx);
  int ret = crypto_sign(cctx, out_sign, (unsigned long long *)&out_sign_len,
                        message, SPX_MLEN, sk);
  if ((uint32_t)out_sign_len != sphincs_plus_get_sign_size(cctx)) {
    return 1;
  }
  return ret;
}

#endif  // CKB_VM

int sphincs_plus_verify(crypto_context *cctx, uint8_t *sign, uint32_t sign_size,
                        uint8_t *message, uint32_t message_size,
                        uint8_t *pubkey, uint32_t pubkey_size) {
  size_t sign_len = sphincs_plus_get_sign_size(cctx);

  if (sign_size != sign_len || message_size != SPX_MLEN ||
      pubkey_size != sphincs_plus_get_pk_size(cctx)) {
    return SphincsPlusError_Params;
  }
  unsigned char mout[SPX_BYTES + SPX_MLEN];
  unsigned long long mlen = 0;

  int err = crypto_sign_open(cctx, mout, &mlen, sign, sign_len, pubkey);
  if (err != 0) {
    return SphincsPlusError_Verify;
  }

  if (mlen != SPX_MLEN) {
    return SphincsPlusError_Verify_MsgLen;
  }

  if (memcmp(mout, message, SPX_MLEN) != 0) {
    return SphincsPlusError_Verify_MsgCmp;
  }

  return 0;
}
