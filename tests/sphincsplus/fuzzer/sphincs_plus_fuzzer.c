#include "sphincs_plus_fuzzer.h"

#include "ckb-sphincsplus.h"

int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {
  uint8_t pubkey[SPX_PK_BYTES] = {0};
  uint8_t message[SPX_MLEN] = {0};

  uint8_t sign[SPX_BYTES + SPX_MLEN] = {0};
  size_t sign_len = sizeof(sign);

  int ret = sphincs_plus_verify(sign, message, pubkey);
  if (ret == 0) return 0;

  // TODO
  return 0;
}