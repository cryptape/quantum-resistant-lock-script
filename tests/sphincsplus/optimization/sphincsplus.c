
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include "ckb-sphincsplus.h"
#include "ckb_vm_dbg.h"
#include "randombytes.h"

const char* G_SPHINCS_PLUS_INFO = "sp_info.txt";

int store_key(uint8_t* pk, uint8_t* sk) {
  int f = 0;
  f = open(G_SPHINCS_PLUS_INFO, O_WRONLY);
  if (f <= 0) {
    f = open(G_SPHINCS_PLUS_INFO, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
    if (f <= 0) {
      printf("can not open keypair file\n");
      return 1;
    }
  }

  write(f, pk, SPX_PK_BYTES);
  write(f, sk, SPX_SK_BYTES);

  close(f);
  return 0;
}

int store_sign(uint8_t* sign, uint8_t* message) {
  int f = open(G_SPHINCS_PLUS_INFO, O_WRONLY);
  if (f <= 0) {
    printf("can not open keypair file\n");
    return 1;
  }

  lseek(f, SPX_PK_BYTES + SPX_SK_BYTES, SEEK_SET);
  write(f, sign, SPX_BYTES + SPX_MLEN);
  write(f, message, SPX_MLEN);

  close(f);
  return 0;
}

int load_sk(uint8_t* sk) {
  int f = open(G_SPHINCS_PLUS_INFO, O_RDONLY);
  if (f == 0) {
    printf("open keypair failed\n");
    return 1;
  }

  lseek(f, SPX_PK_BYTES, SEEK_SET);
  read(f, sk, SPX_SK_BYTES);

  close(f);
  return 0;
}

int load_pk(uint8_t* pk) {
  int f = open(G_SPHINCS_PLUS_INFO, O_RDONLY);
  if (f == 0) {
    printf("open keypair failed\n");
    return 1;
  }

  read(f, pk, SPX_PK_BYTES);

  close(f);
  return 0;
}

int load_sign(uint8_t* sign, uint8_t* message) {
  int f = open(G_SPHINCS_PLUS_INFO, O_RDONLY);
  if (f == 0) {
    printf("open sign failed\n");
    return 1;
  }

  lseek(f, SPX_PK_BYTES + SPX_SK_BYTES, SEEK_SET);
  read(f, sign, SPX_BYTES + SPX_MLEN);
  read(f, message, SPX_MLEN);

  close(f);
  return 0;
}

#if defined(SP_GEN_KEYPAIR)

int main() {
  uint8_t pk[SPX_PK_BYTES];
  uint8_t sk[SPX_SK_BYTES];

  int ret = sphincs_plus_generate_keypair(pk, sk);
  if (ret) {
    printf("gen keypair failed\n");
    return 1;
  }

  if (store_key(pk, sk)) {
    return 2;
  }

  printf("gen keypair done\n");
  return 0;
}

#elif defined(SP_SIGN)

int main() {
  uint8_t sk[SPX_SK_BYTES] = {0};
  if (load_sk(sk)) {
    return 1;
  }

  uint8_t message[SPX_MLEN] = {0};
  randombytes(message, sizeof(message));

  uint8_t sign[SPX_BYTES + SPX_MLEN] = {0};

  if (sphincs_plus_sign(message, sk, sign)) {
    printf("sign failed\n");
    return 2;
  }

  if (store_sign(sign, message)) {
    return 3;
  }

  printf("sign done\n");
  return 0;
}

#elif defined(SP_VERIFY)

int main() {
  uint8_t pk[SPX_PK_BYTES] = {0};
  if (load_pk(pk)) {
    return 1;
  }

  uint8_t sign[SPX_BYTES + SPX_MLEN] = {0};
  uint8_t message[SPX_MLEN] = {0};
  if (load_sign(sign, message)) {
    return 1;
  }

  printf("this pid: %d\n", getpid());

  getchar();

  // for (int i = 0; i < 1000; i++) {
  if (sphincs_plus_verify(sign, message, pk)) {
    printf("verify failed\n");
    return 2;
  }
  // }

  printf("verify done\n");
  return 0;
}

#endif