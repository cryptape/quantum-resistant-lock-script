#ifndef CKB_ZERO_ESCAPE_ENCODING_H_
#define CKB_ZERO_ESCAPE_ENCODING_H_

#ifndef CKB_ZERO_ESCAPE_ERROR_CODE
#define CKB_ZERO_ESCAPE_ERROR_CODE 90
#endif

/*
 * A simple escape encoder that:
 *
 * * Encodes "\0" to "\xFE\xFF"
 * * Encodes "\xFE" to "\xFE\xFD"
 *
 * The values are carefully chosen so encoding can be done by subtracting 1,
 * and decoding can be done by adding 1(of course prefix will need to be added
 * as well).
 *
 * The encoded string will be free from '\0', and can be used as a C string.
 * Decoding can be done in place for minimal memory consumption.
 */

#include <stdint.h>
#include <string.h>

int zero_escape_encode(const uint8_t *src, size_t src_length, uint8_t *dst,
                       size_t *dst_length) {
  size_t wrote = 0;
  size_t limit = *dst_length;

  for (size_t i = 0; i < src_length; i++) {
    if (src[i] == '\0' || src[i] == (uint8_t)'\xFE') {
      if (wrote + 2 > limit) {
        return CKB_ZERO_ESCAPE_ERROR_CODE;
      }
      dst[wrote++] = '\xFE';
      dst[wrote++] = src[i] - 1;
    } else {
      if (wrote + 1 > limit) {
        return CKB_ZERO_ESCAPE_ERROR_CODE;
      }
      dst[wrote++] = src[i];
    }
  }
  if (wrote + 1 > limit) {
    return CKB_ZERO_ESCAPE_ERROR_CODE;
  }
  dst[wrote++] = '\0';

  *dst_length = wrote;
  return 0;
}

int zero_escape_decode_in_place(uint8_t *buffer, size_t *length) {
  size_t wrote = 0;
  size_t limit = *length;

  for (size_t i = 0; i < limit;) {
    if (buffer[i] == (uint8_t)'\xFE') {
      if (i + 1 >= limit) {
        return CKB_ZERO_ESCAPE_ERROR_CODE;
      }
      buffer[wrote++] = buffer[i + 1] + 1;

      i += 2;
    } else {
      buffer[wrote++] = buffer[i++];
    }
  }

  *length = wrote;
  return 0;
}

int zero_escape_decode_cstring_in_place(char *buffer, size_t *out_length) {
  size_t length = strlen(buffer);
  int err = zero_escape_decode_in_place((uint8_t *)buffer, &length);
  if (err != 0) {
    return err;
  }
  *out_length = length;
  return 0;
}

#endif /* CKB_ZERO_ESCAPE_ENCODING_H_ */
