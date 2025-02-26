
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
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
    exit(-1);                                    \
  }
#endif  // ASSERT

void test_all() {
  uint32_t pubkey_len = SPHINCS_PLUS_PK_SIZE;
  uint8_t pubkey[pubkey_len];
  memset(pubkey, 0, pubkey_len);
  uint8_t prikey[SPHINCS_PLUS_SK_SIZE];
  memset(prikey, 0, SPHINCS_PLUS_SK_SIZE);
  int ret = sphincs_plus_generate_keypair(pubkey, prikey);
  ASSERT(ret == 0);
  uint8_t message[100];
  randombytes(message, sizeof(message));
  uint32_t sign_len = SPHINCS_PLUS_SIGN_SIZE;
  uint8_t sign[sign_len];
  memset(sign, 0, sign_len);
  ret = sphincs_plus_sign(message, 100, prikey, sign);
  ASSERT(ret == 0);

  clock_t start, end;
  start = clock();

  ret = sphincs_plus_verify(sign, sign_len, message, 100, pubkey,
                            pubkey_len);
  ASSERT(ret == 0);

  end = clock();
  printf("%s  random verify time: %f seconds\n", xstr(TEST_DATA),
         (double)(end - start) / CLOCKS_PER_SEC);
}

int main() {
  test_all();

  printf("TODO: regenerate test data since the algorithm impl was updated\n");
  /* TODO: regenerate test data since the algorithm impl was updated
  clock_t start, end;
  start = clock();

  int ret =
      sphincs_plus_verify(G_TEST_DATA_SIGN, SPHINCS_PLUS_SIGN_SIZE,
                          G_TEST_DATA_MSG, sizeof(G_TEST_DATA_MSG),
                          G_TEST_DATA_PUB_KEY, sizeof(G_TEST_DATA_PUB_KEY));
  ASSERT(ret == 0);

  end = clock();
  printf("%s  test data verify time: %f seconds\n", xstr(TEST_DATA),
         (double)(end - start) / CLOCKS_PER_SEC);
  */

  return 0;
}

#undef RUN_SHAKE_TEST
#undef RUN_TESTCASE
