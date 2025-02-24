

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
  SphincsPlusError_OutputSignLength,
};

#ifndef CKB_VM

#include <stdlib.h>

int sphincs_plus_generate_keypair(uint8_t *pk, uint8_t *sk) {
  return crypto_sign_keypair(pk, sk);
}

int sphincs_plus_sign(const uint8_t *message, const uint8_t *sk,
                      uint8_t *out_sign) {
  size_t out_sign_len = 0;
  int ret =
      crypto_sign_signature(out_sign, &out_sign_len, message, SPX_MLEN, sk);
  if (ret != 0) {
    return ret;
  }
  if ((uint32_t)out_sign_len != SPHINCS_PLUS_SIGN_SIZE) {
    return SphincsPlusError_OutputSignLength;
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

  int err = crypto_sign_verify(sign, SPHINCS_PLUS_SIGN_SIZE, message,
                               message_size, pubkey);
  if (err != 0) {
    return SphincsPlusError_Verify;
  }

  return 0;
}
