

#include <stdint.h>

#include "context.h"
#include "params.h"
#include "thash.h"
#include "utils.h"

//
// #include "thash_shake_robust.c"

// //
#include "api.h"
#include "fors.h"
#include "wotsx1.h"

#define SPX_MLEN 32
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

int sphincs_plus_verify(uint8_t *sign, size_t sign_len, uint8_t *pubkey) {
  unsigned char mout[SPX_BYTES + SPX_MLEN] = {0};
  unsigned long long mlen = 0;

  return crypto_sign_open(mout, &mlen, sign, sign_len, pubkey);
}
