

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

uint32_t sphincs_plus_get_pk_size() { return SPX_PK_BYTES; }
uint32_t sphincs_plus_get_sk_size() { return SPX_SK_BYTES; }
uint32_t sphincs_plus_get_sign_size() { return SPX_BYTES + SPX_MLEN; }

int sphincs_plus_init(crypto_type type) { return crypto_init_context(type); }

#ifndef CKB_VM

int sphincs_plus_generate_keypair(uint8_t *pk, uint8_t *sk) {
  return crypto_sign_keypair(pk, sk);
}

int sphincs_plus_sign(uint8_t *message, uint8_t *sk, uint8_t *out_sign) {
  unsigned long long out_sign_len = sphincs_plus_get_sign_size();
  int ret = crypto_sign(out_sign, (unsigned long long *)&out_sign_len, message,
                        SPX_MLEN, sk);
  if ((uint32_t)out_sign_len != sphincs_plus_get_sign_size()) {
    return 1;
  }
  return ret;
}

#endif  // CKB_VM

int sphincs_plus_verify(uint8_t *sign, uint32_t sign_size, uint8_t *message,
                        uint32_t message_size, uint8_t *pubkey,
                        uint32_t pubkey_size) {
  if (sign_size != sphincs_plus_get_sign_size() || message_size != SPX_MLEN ||
      pubkey_size != sphincs_plus_get_pk_size()) {
    return SphincsPlusError_Params;
  }
  unsigned char mout[SPX_BYTES + SPX_MLEN];
  unsigned long long mlen = 0;

  size_t sign_len = sphincs_plus_get_sign_size();
  int err = crypto_sign_open(mout, &mlen, sign, sign_len, pubkey);
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
