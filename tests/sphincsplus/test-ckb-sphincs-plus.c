
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
  uint8_t pubkey[get_pk_size()];
  memset(pubkey, 0, get_pk_size());
  uint8_t prikey[get_sk_size()];
  memset(prikey, 0, get_sk_size());
  int ret = sphincs_plus_generate_keypair(pubkey, prikey);
  assert(ret == 0);
  uint8_t message[SPX_MLEN];
  randombytes(message, sizeof(message));
  uint8_t sign[get_sign_size()];
  memset(sign, 0, get_sign_size());
  ret = sphincs_plus_sign(message, prikey, sign);
  assert(ret == 0);
  ret = sphincs_plus_verify(sign, message, pubkey);
  assert(ret == 0);
}

int main() {
#define RUN_TESTCASE(hash_name, hash_size, hash_option, thash)         \
  {                                                                    \
    clock_t start, end;                                                \
    start = clock();                                                   \
    crypto_init_context(                                               \
        CRYPTO_TYPE_##hash_name##_##hash_size##hash_option##_##thash); \
                                                                       \
    test_all();                                                        \
                                                                       \
    int ret = sphincs_plus_verify(                                     \
        G_##hash_name##_##hash_size##hash_option##_##thash##_SIGN,     \
        G_##hash_name##_##hash_size##hash_option##_##thash##_MSG,      \
        G_##hash_name##_##hash_size##hash_option##_##thash##_PUB_KEY); \
    assert(ret == 0);                                                  \
    end = clock();                                                     \
    printf("%s-%s%s-%s  time:%f\n", xstr(hash_name), xstr(hash_size),  \
           xstr(hash_option), xstr(thash),                             \
           (double)(end - start) / CLOCKS_PER_SEC);                    \
  }

#define RUN_SHAKE_TEST(size)            \
  RUN_TESTCASE(SHAKE, size, S, ROBUST); \
  RUN_TESTCASE(SHAKE, size, F, ROBUST); \
  RUN_TESTCASE(SHAKE, size, S, SIMPLE); \
  RUN_TESTCASE(SHAKE, size, F, SIMPLE);

  // shake
  RUN_SHAKE_TEST(128);
  RUN_SHAKE_TEST(192);
  RUN_SHAKE_TEST(256);

#undef RUN_SHAKE_TEST
#undef RUN_TESTCASE
  return 0;
}