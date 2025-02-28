#include <stdio.h>

#include "ckb-sphincsplus.h"

int main() {
  printf("#define CKB_SPHINCS_PARAM%d_PK_BYTES %d\n", PARAMS_ID,
         SPHINCS_PLUS_PK_SIZE);
  printf("#define CKB_SPHINCS_PARAM%d_SIGN_BYTES %d\n", PARAMS_ID,
         SPHINCS_PLUS_SIGN_SIZE);

  return 0;
}
