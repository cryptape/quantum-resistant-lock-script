#ifndef _C_CKB_VM_DBG_H_
#define _C_CKB_VM_DBG_H_
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

static void print_buf(uint8_t *buf, size_t len, const char *name) {
  const int max = 32;
  printf("%s, len: %zu\n", name, len);
  for (size_t i = 0; i < len; i++) {
    printf("%02x, ", buf[i]);
    if (i % max == (max - 1)) {
      printf("\n");
    }
  }
  printf("\n");
}

#define PRINT_BUF(buf) print_buf(buf, sizeof(buf), #buf);


#endif  //_C_CKB_VM_DBG_H_