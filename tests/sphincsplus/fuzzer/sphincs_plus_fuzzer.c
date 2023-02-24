#include "sphincs_plus_fuzzer.h"

#include <string.h>

#include "ckb-sphincsplus.h"

size_t fill_buf(uint8_t *buf, size_t buf_size, uint8_t *data, size_t size) {
  if (size == 0) {
    memset(buf, 0, buf_size);
    return 0;
  } else if (size >= buf_size) {
    memcpy(buf, data, buf_size);
    return buf_size;
  } else {
    memcpy(buf, data, size);
    buf += size;
    memset(buf, 0, buf_size - size);
    return size;
  }
}

int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {
  uint8_t message[SPX_MLEN];

  uint32_t pubkey_size = sphincs_plus_get_pk_size();
  uint8_t pubkey[pubkey_size];

  uint32_t sign_size = sphincs_plus_get_sign_size();
  uint8_t sign[sign_size];

  size_t offset = fill_buf(message, SPX_MLEN, data, size);
  data += offset;
  size -= offset;

  offset = fill_buf(pubkey, pubkey_size, data, size);
  data += offset;
  size -= offset;

  offset = fill_buf(sign, sign_size, data, size);
  data += offset;
  size -= offset;

  int err = sphincs_plus_verify(sign, sign_size, message, SPX_MLEN, pubkey,
                                pubkey_size);
  if (err != 0) {
    return 0;
  };

  return 0;
}