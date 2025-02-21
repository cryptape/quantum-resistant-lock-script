#include <stdio.h>

#include "ckb-sphincsplus.h"

int main() {
  printf("#define PARAM%d_PK_BYTES %d\n", PARAMS_ID,
         sphincs_plus_get_pk_size());
  printf("#define PARAM%d_SIGN_BYTES %d\n", PARAMS_ID,
         sphincs_plus_get_sign_size());

  return 0;
}
