
#ifdef CKB_VM
#undef CKB_DECLARATION_ONLY
#include "entry.h"
#define CKB_DECLARATION_ONLY
#include "ckb_syscalls.h"
#endif  // __RISCV64__

//
#include <stdio.h>

#include "ckb-sphincsplus.h"
#include "randombytes.h"

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

#ifdef CKB_VM
int run_ckb_vm() { return 0; }
#else   // CKB_VM
int run_native() {
  uint8_t pk[SPX_PK_BYTES] = {0};
  uint8_t sk[SPX_SK_BYTES] = {0};

  int ref = sphincs_plus_generate_keypair(pk, sk);
  if (ref != 0) {
    printf("generate keypair, code: %d\n", ref);
    return 1;
  }

  uint8_t message[SPX_MLEN] = {0};
  randombytes(message, SPX_MLEN);

  uint8_t sign[SPX_BYTES + SPX_MLEN] = {0};
  size_t sign_len = sizeof(sign);
  ref = sphincs_plus_sign(message, sk, sign, &sign_len);
  if (ref != 0) {
    printf("sign, code: %d\n", ref);
    return 1;
  }

  ref = sphincs_plus_verify(sign, sign_len, pk);
  if (ref != 0) {
    printf("verify failed, code: %d\n", ref);
    return 1;
  }

  return 0;
}
#endif  // CKB_VM

int main() {
#ifdef CKB_VM
  return run_ckb_vm();
#else
  return run_native();
#endif
}

// int generate_sighash_all(uint8_t *msg) {
//   int err = CKB_SUCCESS;

//   uint64_t len = 0;
//   uint8_t temp[MAX_WITNESS_SIZE] = {0};

//   uint64_t read_len = MAX_WITNESS_SIZE;
//   uint64_t witness_len = MAX_WITNESS_SIZE;

//   // Load witness of first input
//   err = ckb_load_witness(temp, &read_len, 0, 0, CKB_SOURCE_GROUP_INPUT);
//   if (CUDT_IS_FAILED(err)) return CUDTERR_WITNESS_INVALID;

//   witness_len = read_len;
//   if (read_len > MAX_WITNESS_SIZE) {
//     read_len = MAX_WITNESS_SIZE;
//   }

//   // load signature
//   mol_seg_t lock_bytes_seg;
//   err = extract_witness_lock(temp, read_len, &lock_bytes_seg);
//   if (CUDT_IS_FAILED(err)) return CUDTERR_WITNESS_INVALID;

//   // Load tx hash
//   unsigned char tx_hash[BLAKE2B_BLOCK_SIZE] = {0};
//   len = BLAKE2B_BLOCK_SIZE;
//   err = ckb_load_tx_hash(tx_hash, &len, 0);
//   if (CUDT_IS_FAILED(err)) return CUDTERR_WITNESS_INVALID;

//   if (len != BLAKE2B_BLOCK_SIZE) return CUDTERR_WITNESS_INVALID;

//   // Prepare sign message
//   blake2b_state blake2b_ctx;
//   err = blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
//   CUDT_CHECK_BLAKE(err);

//   err = blake2b_update(&blake2b_ctx, tx_hash, BLAKE2B_BLOCK_SIZE);
//   CUDT_CHECK_BLAKE(err);

//   // Clear lock field to zero, then digest the first witness
//   // lock_bytes_seg.ptr actually points to the memory in temp buffer
//   memset((void *)lock_bytes_seg.ptr, 0, lock_bytes_seg.size);
//   err = blake2b_update(&blake2b_ctx, (char *)&witness_len, sizeof(uint64_t));
//   CUDT_CHECK_BLAKE(err);

//   err = blake2b_update(&blake2b_ctx, temp, read_len);
//   CUDT_CHECK_BLAKE(err);

//   // remaining of first witness
//   if (read_len < witness_len) {
//     err = load_and_hash_witness(&blake2b_ctx, read_len, 0,
//                                 CKB_SOURCE_GROUP_INPUT, false);
//     if (CUDT_IS_FAILED(err)) return CUDTERR_WITNESS_INVALID;
//   }

//   // CKB_SOURCE_GROUP_INPUT <= 1 in this cell
//   size_t i = 1;
//   while (1) {
//     err =
//         load_and_hash_witness(&blake2b_ctx, 0, i, CKB_SOURCE_GROUP_INPUT, true);
//     if (err == CKB_INDEX_OUT_OF_BOUND) {
//       break;
//     }
//     if (err != CKB_SUCCESS) {
//       return CKB_INVALID_DATA;
//     }
//     i += 1;
//   }

//   // Digest witnesses that not covered by inputs
//   size_t i = (size_t)ckb_calculate_inputs_len();
//   while (1) {
//     err = load_and_hash_witness(&blake2b_ctx, 0, i, CKB_SOURCE_INPUT, true);
//     if (err == CKB_INDEX_OUT_OF_BOUND) {
//       break;
//     }
//     if (err != CKB_SUCCESS) {
//       return CKB_INVALID_DATA;
//     }
//     i += 1;
//   }

//   err = blake2b_final(&blake2b_ctx, msg, BLAKE2B_BLOCK_SIZE);
//   CUDT_CHECK_BLAKE(err);

//   return CKB_SUCCESS;
// }