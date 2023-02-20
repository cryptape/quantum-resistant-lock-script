#include "sphincs_plus_fuzzer.h"

#include <string.h>

#include "ckb-sphincsplus.h"

typedef enum {
  SphincsFuzz_Success = 0,
  SphincsFuzz_Init,
} SphincsFuzzError;

size_t fill_buf(uint8_t *buf, size_t buf_size, uint8_t *data, size_t size) {
  if (size == 0) {
    memset(buf, 0, buf_size);
  } else if (size >= buf_size) {
    memcpy(buf, data, buf_size);
  } else {
    memcpy(buf, data, size);
    buf += size;
    memset(buf, 0, buf_size - size);
  }
}

int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {
  uint32_t hash_type = 0;
  if (size > 0) {
    hash_type = data[0];
  }
  data += 1;
  size -= 1;

  int err = sphincs_plus_init(hash_type);
  if (err != 0) {
    return SphincsFuzz_Success;
  }

  uint8_t message[SPX_MLEN];
  uint8_t pubkey[sphincs_plus_get_pk_size()];
  uint8_t sign[sphincs_plus_get_sign_size()];

  size_t offset = fill_buf(message, SPX_MLEN, data, size);
  data += offset;
  size -= offset;

  offset = fill_buf(pubkey, sphincs_plus_get_pk_size(), data, size);
  data += offset;
  size -= offset;

  offset = fill_buf(sign, sphincs_plus_get_sign_size(), data, size);
  data += offset;
  size -= offset;

  err = sphincs_plus_verify(sign, message, pubkey);
  if (err == 0) {
    return SphincsFuzz_Success;
  };

  return SphincsFuzz_Success;
}