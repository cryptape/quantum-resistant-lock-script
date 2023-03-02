#undef CKB_DECLARATION_ONLY
#include "entry.h"
#define CKB_DECLARATION_ONLY

#include <ckb_syscalls.h>
#include <stdio.h>

#include "ckb-sphincsplus.h"
#include "test_data.h"

#undef ASSERT
// #define ASSERT(s)
#define ASSERT(s) (void)0

void randombytes(unsigned char *x, unsigned long long xlen) { ASSERT(0); }

int main() {
  int err =
      sphincs_plus_verify(G_TEST_DATA_SIGN, sizeof(G_TEST_DATA_SIGN),
                          G_TEST_DATA_MSG, sizeof(G_TEST_DATA_MSG),
                          G_TEST_DATA_PUB_KEY, sizeof(G_TEST_DATA_PUB_KEY));
  if (err != 0) {
    return 2;
  }

  printf("PubKey size: %d, Sign size: %d\n", sizeof(G_TEST_DATA_PUB_KEY),
         sizeof(G_TEST_DATA_SIGN));
  // printf("Done");
  return 0;
}
