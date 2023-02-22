#undef CKB_DECLARATION_ONLY
#include "entry.h"
#define CKB_DECLARATION_ONLY

#include <ckb_syscalls.h>
#include <stdio.h>

#include "ckb-sphincsplus.h"
#include "ckb_vm_dbg.h"
#include "test_data.h"

#define RUN_SPHINCS_PLUS(NAME, SIZE, OPTION, THASH)           \
  err = sphincs_plus_init_context(                            \
      CRYPTO_TYPE_##NAME##_##SIZE##OPTION##_##THASH, &cctx);  \
  if (err != 0) {                                             \
    return 1;                                                 \
  }                                                           \
  err = sphincs_plus_verify(                                  \
      &cctx, G_##NAME##_##SIZE##OPTION##_##THASH##_SIGN,      \
      sizeof(G_##NAME##_##SIZE##OPTION##_##THASH##_SIGN),     \
      G_##NAME##_##SIZE##OPTION##_##THASH##_MSG,              \
      sizeof(G_##NAME##_##SIZE##OPTION##_##THASH##_MSG),      \
      G_##NAME##_##SIZE##OPTION##_##THASH##_PUB_KEY,          \
      sizeof(G_##NAME##_##SIZE##OPTION##_##THASH##_PUB_KEY)); \
  if (err != 0) {                                             \
    return 2;                                                 \
  }

int main() {
  crypto_context cctx = {0};
  int err = 0;
  // RUN_SPHINCS_PLUS(SHAKE, 128, S, ROBUST);
  // RUN_SPHINCS_PLUS(SHAKE, 192, S, ROBUST);
  // RUN_SPHINCS_PLUS(SHAKE, 256, S, ROBUST);

  // RUN_SPHINCS_PLUS(SHAKE, 128, F, ROBUST);
  // RUN_SPHINCS_PLUS(SHAKE, 192, F, ROBUST);
  RUN_SPHINCS_PLUS(SHAKE, 256, F, ROBUST);

  // RUN_SPHINCS_PLUS(SHAKE, 128, S, SIMPLE);
  // RUN_SPHINCS_PLUS(SHAKE, 192, S, SIMPLE);
  // RUN_SPHINCS_PLUS(SHAKE, 256, S, SIMPLE);

  // RUN_SPHINCS_PLUS(SHAKE, 128, F, SIMPLE);
  // RUN_SPHINCS_PLUS(SHAKE, 192, F, SIMPLE);
  // RUN_SPHINCS_PLUS(SHAKE, 256, F, SIMPLE);

  printf("Done");
  return 0;
}
