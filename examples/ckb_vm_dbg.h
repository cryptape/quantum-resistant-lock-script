#include <stdio.h>

void print_buf(uint8_t *buf, size_t len, const char *name) {
  const int max = 32;
  printf("%s, len: %zu\n", name, len);
  for (int i = 0; i < len; i++) {
    printf("%02x, ", buf[i]);
    if (i % max == (max - 1)) {
      printf("\n");
    }
  }
}

#define PRINT_BUF(buf) print_buf(buf, sizeof(buf), #buf);
