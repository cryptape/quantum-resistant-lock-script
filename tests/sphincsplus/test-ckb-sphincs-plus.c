
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "api.h"
#include "ckb-sphincsplus.h"
#include "params.h"
#include "randombytes.h"
#include "test_data.h"

#ifndef ASSERT
#define ASSERT(c)                                \
  if (!(c)) {                                    \
    printf("Assert: %s:%d", __FILE__, __LINE__); \
    ((void)0);                                   \
  }
#endif  // ASSERT

void test_all() {
  uint32_t pubkey_len = sphincs_plus_get_pk_size();
  uint8_t pubkey[pubkey_len];
  memset(pubkey, 0, pubkey_len);
  uint8_t prikey[sphincs_plus_get_sk_size()];
  memset(prikey, 0, sphincs_plus_get_sk_size());
  int ret = sphincs_plus_generate_keypair(pubkey, prikey);
  ASSERT(ret == 0);
  uint8_t message[SPX_MLEN];
  randombytes(message, sizeof(message));
  uint32_t sign_len = sphincs_plus_get_sign_size();
  uint8_t sign[sign_len];
  memset(sign, 0, sign_len);
  ret = sphincs_plus_sign(message, prikey, sign);
  ASSERT(ret == 0);
  ret = sphincs_plus_verify(sign, sign_len, message, SPX_MLEN, pubkey,
                            pubkey_len);
  ASSERT(ret == 0);
}

int main() {
  clock_t start, end;
  start = clock();
  test_all();

  int ret =
      sphincs_plus_verify(G_TEST_DATA_SIGN, sizeof(G_TEST_DATA_SIGN),
                          G_TEST_DATA_MSG, sizeof(G_TEST_DATA_MSG),
                          G_TEST_DATA_PUB_KEY, sizeof(G_TEST_DATA_PUB_KEY));
  ASSERT(ret == 0);
  end = clock();
  printf("%s-%s%s-%s  time:%f\n", xstr(NAME), xstr(size), xstr(OPTION),
         xstr(THASH), (double)(end - start) / CLOCKS_PER_SEC);

  return 0;
}

#undef RUN_SHAKE_TEST
#undef RUN_TESTCASE