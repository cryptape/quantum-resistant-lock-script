
#include <assert.h>
#include <string.h>

#include "api.h"
#include "ckb-sphincsplus.h"
#include "params.h"
#include "randombytes.h"

int main() {
  crypto_init_context(CRYPTO_TYPE_SHAKE_256F_ROBUST);

  uint8_t pubkey[get_pk_size()];
  memset(pubkey, 0, get_pk_size());

  uint8_t prikey[get_sk_size()];
  memset(prikey, 0, get_sk_size());

  int ret = sphincs_plus_generate_keypair(pubkey, prikey);
  assert(ret == 0);

  uint8_t message[SPX_MLEN] = {0};
  randombytes(message, sizeof(message));

  uint8_t sign[get_sign_size()];
  ret = sphincs_plus_sign(message, prikey, sign);
  assert(ret == 0);

  ret = sphincs_plus_verify(sign, message, pubkey);
  assert(ret == 0);

  return 0;
}