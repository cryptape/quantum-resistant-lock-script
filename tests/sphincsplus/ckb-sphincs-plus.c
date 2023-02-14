
#include <assert.h>

#include "ckb-sphincsplus.h"
#include "randombytes.h"

int main() {
  uint8_t pubkey[SPX_PK_BYTES] = {0};
  uint8_t prikey[SPX_SK_BYTES] = {0};
  int ret = sphincs_plus_generate_keypair(pubkey, prikey);
  assert(ret == 0);

  uint8_t message[SPX_MLEN] = {0};
  randombytes(message, sizeof(message));

  uint8_t sign[SPX_BYTES + SPX_MLEN] = {0};
  ret = sphincs_plus_sign(message, prikey, sign);
  assert(ret == 0);

  ret = sphincs_plus_verify(sign, message, pubkey);
  assert(ret == 0);

  return 0;
}