
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "api.h"
#include "ckb-sphincsplus.h"
#include "params.h"
#include "randombytes.h"
#include "test_data.h"

void test_all() {
  uint8_t pubkey[sphincs_plus_get_pk_size()];
  memset(pubkey, 0, sphincs_plus_get_pk_size());
  uint8_t prikey[sphincs_plus_get_sk_size()];
  memset(prikey, 0, sphincs_plus_get_sk_size());
  int ret = sphincs_plus_generate_keypair(pubkey, prikey);
  ASSERT(ret == 0);
  uint8_t message[SPX_MLEN];
  randombytes(message, sizeof(message));
  uint8_t sign[sphincs_plus_get_sign_size()];
  memset(sign, 0, sphincs_plus_get_sign_size());
  ret = sphincs_plus_sign(message, prikey, sign);
  ASSERT(ret == 0);
  ret = sphincs_plus_verify(sign, message, pubkey);
  ASSERT(ret == 0);
}

#define RUN_TESTCASE(NAME, size, OPTION, THASH)                             \
  {                                                                         \
    clock_t start, end;                                                     \
    start = clock();                                                        \
    crypto_init_context(CRYPTO_TYPE_##NAME##_##size##OPTION##_##THASH);     \
                                                                            \
    test_all();                                                             \
                                                                            \
    int ret =                                                               \
        sphincs_plus_verify(G_##NAME##_##size##OPTION##_##THASH##_SIGN,     \
                            G_##NAME##_##size##OPTION##_##THASH##_MSG,      \
                            G_##NAME##_##size##OPTION##_##THASH##_PUB_KEY); \
    ASSERT(ret == 0);                                                       \
    end = clock();                                                          \
    printf("%s-%s%s-%s  time:%f\n", xstr(NAME), xstr(size), xstr(OPTION),   \
           xstr(THASH), (double)(end - start) / CLOCKS_PER_SEC);            \
  }

#define RUN_HASH_TEST(NAME, size) RUN_TESTCASE(NAME, size, F, ROBUST);

// RUN_TESTCASE(NAME, size, F, SIMPLE);
// RUN_TESTCASE(NAME, size, S, ROBUST);
// RUN_TESTCASE(NAME, size, S, SIMPLE);
// All tests are too time consuming

int main() {
  // shake
  RUN_HASH_TEST(SHAKE, 128);
  RUN_HASH_TEST(SHAKE, 192);
  RUN_HASH_TEST(SHAKE, 256);

  // sha2
  RUN_HASH_TEST(SHA2, 128);
  RUN_HASH_TEST(SHA2, 192);
  RUN_HASH_TEST(SHA2, 256);

  // haraka
  RUN_HASH_TEST(HARAKA, 128);
  RUN_HASH_TEST(HARAKA, 192);
  RUN_HASH_TEST(HARAKA, 256);

  return 0;
}

#undef RUN_SHAKE_TEST
#undef RUN_TESTCASE