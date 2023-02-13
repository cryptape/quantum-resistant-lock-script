

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

#define SPX_MLEN 32

uint32_t get_pk_size() { return SPX_PK_BYTES; }
uint32_t get_sk_size() { return SPX_SK_BYTES; }
uint32_t get_sign_size() { return SPX_BYTES + SPX_MLEN; }

#ifndef CKB_VM

int sphincs_plus_generate_keypair(uint8_t *pk, uint8_t *sk) {
  return crypto_sign_keypair(pk, sk);
}

int sphincs_plus_sign(uint8_t *message, uint8_t *sk, uint8_t *out_sign,
                      size_t *out_sign_len) {
  return crypto_sign(out_sign, (unsigned long long *)out_sign_len, message,
                     SPX_MLEN, sk);
}

#endif  // CKB_VM

int sphincs_plus_verify(uint8_t *sign, size_t sign_len, uint8_t *message,
                        uint8_t *pubkey) {
  unsigned char mout[SPX_BYTES + SPX_MLEN] = {0};
  unsigned long long mlen = 0;

  int ret = crypto_sign_open(mout, &mlen, sign, sign_len, pubkey);
  if (ret != 0) {
    return ret;
  }

  if (mlen != SPX_MLEN) {
    return 1;
  }

  if (memcmp(mout, message, SPX_MLEN) != 0) {
    return 2;
  }

  return 0;
}
