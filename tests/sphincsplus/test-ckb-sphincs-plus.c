
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "api.h"
#include "ckb-sphincsplus.h"
#include "params.h"
#include "randombytes.h"
#include "test_data.h"

int main() {
#define RUN_VERIFY_BY_TEST_DATA(hash_name, hash_size, hash_option, thash) \
  {                                                                       \
    crypto_init_context(                                                  \
        CRYPTO_TYPE_##hash_name##_##hash_size##hash_option##_##thash);    \
                                                                          \
    uint8_t pubkey[get_pk_size()];                                        \
    memset(pubkey, 0, get_pk_size());                                     \
    uint8_t prikey[get_sk_size()];                                        \
    memset(prikey, 0, get_sk_size());                                     \
    int ret = sphincs_plus_generate_keypair(pubkey, prikey);              \
    assert(ret == 0);                                                     \
    uint8_t message[SPX_MLEN] = {0};                                      \
    randombytes(message, sizeof(message));                                \
    uint8_t sign[get_sign_size()];                                        \
    ret = sphincs_plus_sign(message, prikey, sign);                       \
    assert(ret == 0);                                                     \
    ret = sphincs_plus_verify(sign, message, pubkey);                     \
    assert(ret == 0);                                                     \
                                                                          \
    ret = sphincs_plus_verify(                                            \
        G_##hash_name##_##hash_size##hash_option##_##thash##_SIGN,        \
        G_##hash_name##_##hash_size##hash_option##_##thash##_MSG,         \
        G_##hash_name##_##hash_size##hash_option##_##thash##_PUB_KEY);    \
    assert(ret == 0);                                                     \
    printf("%s-%s%s-%s\n", xstr(hash_name), xstr(hash_size),              \
           xstr(hash_option), xstr(thash));                               \
  }

  RUN_VERIFY_BY_TEST_DATA(SHAKE, 256, F, ROBUST);
  RUN_VERIFY_BY_TEST_DATA(SHAKE, 256, F, SIMPLE);

#undef RUN_VERIFY_BY_TEST_DATA
  return 0;
}