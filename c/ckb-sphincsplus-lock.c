
#undef CKB_DECLARATION_ONLY
#include "entry.h"
#define CKB_DECLARATION_ONLY

#include <blake2b.h>
#include <ckb_exec.h>
#include <ckb_syscalls.h>
#include <molecule/blockchain.h>
#include <stdio.h>

#include "ckb-sphincsplus.h"
#include "ckb_vm_dbg.h"

#define MAX_WITNESS_SIZE 1024 * 64
#define BLAKE2B_BLOCK_SIZE 32
#define ONE_BATCH_SIZE 1024 * 64

#define SPHINCSPLUS_PUBKEY_SIZE SPX_PK_BYTES
#define SPHINCSPLUS_SIGN_SIZE (SPX_BYTES + SPX_MLEN)

#define SCRIPT_SIZE 1024 * 64  // 32k

#undef ASSERT
// #define ASSERT(s)
#define ASSERT(s) (void)0

#undef CHECK2
#define CHECK2(cond, code) \
  do {                     \
    if (!(cond)) {         \
      err = code;          \
      ASSERT(0);           \
      goto exit;           \
    }                      \
  } while (0)

#undef CHECK
#define CHECK(_code)    \
  do {                  \
    int code = (_code); \
    if (code != 0) {    \
      err = code;       \
      ASSERT(0);        \
      goto exit;        \
    }                   \
  } while (0)

enum SPHINCSPLUS_EXAMPLE_ERROR {
  ERROR_SPHINCSPLUS_ARGUMENTS_LEN = 101,
  ERROR_SPHINCSPLUS_SYSCALL,
  ERROR_SPHINCSPLUS_ENCODING,
  ERROR_SPHINCSPLUS_ARGS,
  ERROR_SPHINCSPLUS_WITNESS,
  ERROR_SPHINCSPLUS_VERIFY,
};

static int extract_witness_lock(uint8_t *witness, uint64_t len,
                                mol_seg_t *lock_bytes_seg) {
  if (len < 20) {
    return ERROR_SPHINCSPLUS_ENCODING;
  }
  uint32_t lock_length = *((uint32_t *)(&witness[16]));
  if (len < 20 + lock_length) {
    return ERROR_SPHINCSPLUS_ENCODING;
  } else {
    lock_bytes_seg->ptr = &witness[20];
    lock_bytes_seg->size = lock_length;
  }
  return CKB_SUCCESS;
}

int load_and_hash_witness(blake2b_state *ctx, size_t start, size_t index,
                          size_t source, bool hash_length) {
  int err = CKB_SUCCESS;
  uint8_t temp[ONE_BATCH_SIZE];
  uint64_t len = ONE_BATCH_SIZE;
  CHECK(ckb_load_witness(temp, &len, start, index, source));
  if (hash_length) {
    blake2b_update(ctx, (char *)&len, sizeof(uint64_t));
  }
  uint64_t offset = (len > ONE_BATCH_SIZE) ? ONE_BATCH_SIZE : len;
  blake2b_update(ctx, temp, offset);
  while (offset < len) {
    uint64_t current_len = ONE_BATCH_SIZE;
    CHECK(ckb_load_witness(temp, &current_len, start + offset, index, source));
    uint64_t current_read =
        (current_len > ONE_BATCH_SIZE) ? ONE_BATCH_SIZE : current_len;
    blake2b_update(ctx, temp, current_read);
    offset += current_read;
  }

exit:
  return err;
}

int generate_sighash_all(uint8_t *msg, size_t msg_len) {
  int err = CKB_SUCCESS;
  uint64_t len = 0;
  unsigned char temp[MAX_WITNESS_SIZE];
  uint64_t read_len = MAX_WITNESS_SIZE;
  uint64_t witness_len = MAX_WITNESS_SIZE;
  CHECK2(msg_len >= BLAKE2B_BLOCK_SIZE, ERROR_SPHINCSPLUS_ARGUMENTS_LEN);

  /* Load witness of first input */
  CHECK(ckb_load_witness(temp, &read_len, 0, 0, CKB_SOURCE_GROUP_INPUT));
  witness_len = read_len;
  if (read_len > MAX_WITNESS_SIZE) {
    read_len = MAX_WITNESS_SIZE;
  }

  /* load signature */
  mol_seg_t lock_bytes_seg;
  CHECK(extract_witness_lock(temp, read_len, &lock_bytes_seg));

  /* Load tx hash */
  unsigned char tx_hash[BLAKE2B_BLOCK_SIZE];
  len = BLAKE2B_BLOCK_SIZE;
  CHECK(ckb_load_tx_hash(tx_hash, &len, 0));
  if (len != BLAKE2B_BLOCK_SIZE) {
    return ERROR_SPHINCSPLUS_SYSCALL;
  }

  /* Prepare sign message */
  blake2b_state blake2b_ctx;
  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&blake2b_ctx, tx_hash, BLAKE2B_BLOCK_SIZE);

  /* Clear lock field to zero, then digest the first witness
   * lock_bytes_seg.ptr actually points to the memory in temp buffer
   * */
  memset((void *)lock_bytes_seg.ptr, 0, lock_bytes_seg.size);
  blake2b_update(&blake2b_ctx, (char *)&witness_len, sizeof(uint64_t));
  blake2b_update(&blake2b_ctx, temp, read_len);

  // remaining of first witness
  if (read_len < witness_len) {
    CHECK(load_and_hash_witness(&blake2b_ctx, read_len, 0,
                                CKB_SOURCE_GROUP_INPUT, false));
  }

  // Digest same group witnesses
  size_t i = 1;
  while (1) {
    err =
        load_and_hash_witness(&blake2b_ctx, 0, i, CKB_SOURCE_GROUP_INPUT, true);
    if (err == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    CHECK(err);
    i += 1;
  }

  // Digest witnesses that not covered by inputs
  i = (size_t)ckb_calculate_inputs_len();
  while (1) {
    err = load_and_hash_witness(&blake2b_ctx, 0, i, CKB_SOURCE_INPUT, true);
    if (err == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    CHECK(err);
    i += 1;
  }
  blake2b_final(&blake2b_ctx, msg, BLAKE2B_BLOCK_SIZE);
  err = CKB_SUCCESS;

exit:
  return err;
}

int get_sign(uint8_t *sign) {
  int err = CKB_SUCCESS;

  uint8_t buf[SPHINCSPLUS_SIGN_SIZE + 56] = {0};
  uint64_t len = sizeof(buf);
  CHECK(ckb_load_witness(buf, &len, 0, 0, CKB_SOURCE_GROUP_INPUT));
  CHECK2((len == sizeof(buf)), ERROR_SPHINCSPLUS_WITNESS);

  memcpy(sign, buf + 20, SPHINCSPLUS_SIGN_SIZE);
exit:
  return err;
}

int get_public_key(uint8_t *buf) {
  int err = CKB_SUCCESS;

  uint8_t script[SCRIPT_SIZE];
  uint64_t script_len = sizeof(script);
  CHECK(ckb_load_script(script, &script_len, 0));

  mol_seg_t script_seg;
  script_seg.ptr = (uint8_t *)script;
  script_seg.size = script_len;

  mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
  mol_seg_t args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);

  CHECK2((args_bytes_seg.size == SPHINCSPLUS_PUBKEY_SIZE),
         ERROR_SPHINCSPLUS_ARGS);
  memcpy(buf, args_bytes_seg.ptr, args_bytes_seg.size);

exit:
  return err;
}

int main() {
  int err = CKB_SUCCESS;
  uint8_t message[BLAKE2B_BLOCK_SIZE] = {0};
  CHECK(generate_sighash_all(message, sizeof(message)));

  uint8_t pubkey[SPHINCSPLUS_PUBKEY_SIZE] = {0};
  CHECK(get_public_key(pubkey));

  uint8_t sign[SPHINCSPLUS_SIGN_SIZE] = {0};
  CHECK(get_sign(sign));

  err = sphincs_plus_verify(sign, message, pubkey);
  CHECK2(err == 0, ERROR_SPHINCSPLUS_VERIFY);

exit:
  return err;
}
