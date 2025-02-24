

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

// TODO: switch the code to use crypto_sign_signature / crypto_sign_verify,
// so we don't need to append message to the end of the signature.

#include <stdlib.h>

int sphincs_plus_generate_keypair(uint8_t *pk, uint8_t *sk) {
  return crypto_sign_keypair(pk, sk);
}

int sphincs_plus_sign(const uint8_t *message, const uint8_t *sk,
                      uint8_t *out_sign) {
  unsigned long long out_sign_len = SPHINCS_PLUS_SIGN_SIZE;
  int ret = crypto_sign(out_sign, (unsigned long long *)&out_sign_len, message,
                        SPX_MLEN, sk);
  if ((uint32_t)out_sign_len != SPHINCS_PLUS_SIGN_SIZE) {
    return 1;
  }
  return ret;
}

/* Defined for Rust FFI usage, script code would only require the macros */
uint32_t sphincs_plus_get_pk_size() { return SPHINCS_PLUS_PK_SIZE; }
uint32_t sphincs_plus_get_sk_size() { return SPHINCS_PLUS_SK_SIZE; }
uint32_t sphincs_plus_get_sign_size() { return SPHINCS_PLUS_SIGN_SIZE; }

#endif  // CKB_VM

int sphincs_plus_verify(const uint8_t *sign, uint32_t sign_size,
                        const uint8_t *message, uint32_t message_size,
                        const uint8_t *pubkey, uint32_t pubkey_size) {
  if (sign_size != SPHINCS_PLUS_SIGN_SIZE || message_size != SPX_MLEN ||
      pubkey_size != SPHINCS_PLUS_PK_SIZE) {
    return SphincsPlusError_Params;
  }
  unsigned char mout[SPX_BYTES + SPX_MLEN];
  unsigned long long mlen = 0;

  int err = crypto_sign_open(mout, &mlen, sign, SPHINCS_PLUS_SIGN_SIZE, pubkey);
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
