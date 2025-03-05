#ifndef CKB_SPHINCSPLUS_COMMON_H
#define CKB_SPHINCSPLUS_COMMON_H

/*
 * Common definitions shared by CKB sphincs+ locks
 */

#define BLAKE2B_BLOCK_SIZE 32
#define ONE_BATCH_SIZE 1024 * 64
#define MAX_WITNESS_SIZE ONE_BATCH_SIZE
#define SCRIPT_SIZE ONE_BATCH_SIZE

#define MULTISIG_RESERVED_FIELD_VALUE 0x80
#define MULTISIG_HAS_SIGNATURE(flag) ((flag & 1) != 0)
#define MULTISIG_SIGN_FLAG(flag) (flag & 0xFE)
#define MULTISIG_FLAG_TO_PARAM_ID(flag) (flag >> 1)
#define MULTISIG_PARAM_ID_TO_INDEX(id) (id - CKB_SPHINCS_MIN_PARAM_ID)
#define MULTISIG_FLAG_TO_PARAM_INDEX(flag) \
  MULTISIG_PARAM_ID_TO_INDEX(MULTISIG_FLAG_TO_PARAM_ID(flag))

#ifndef MOL2_EXIT
#define MOL2_EXIT ckb_exit
#endif

#undef ASSERT
#define ASSERT(s)                             \
  do {                                        \
    if (!(s)) {                               \
      ckb_exit(ERROR_SPHINCSPLUS_UNEXPECTED); \
    }                                         \
  } while (0)

#undef CHECK2
#define CHECK2(cond, code) \
  do {                     \
    if (!(cond)) {         \
      err = code;          \
      goto exit;           \
    }                      \
  } while (0)

#undef CHECK
#define CHECK(_code)    \
  do {                  \
    int code = (_code); \
    if (code != 0) {    \
      err = code;       \
      goto exit;        \
    }                   \
  } while (0)

enum SPHINCSPLUS_EXAMPLE_ERROR {
  ERROR_SPHINCSPLUS_ARGUMENTS_LEN = 101,
  ERROR_SPHINCSPLUS_MESSAGE,
  ERROR_SPHINCSPLUS_ENCODING,
  ERROR_SPHINCSPLUS_ARGS,
  ERROR_SPHINCSPLUS_MULTISIG_HASH,
  ERROR_SPHINCSPLUS_WITNESS,
  ERROR_SPHINCSPLUS_VERIFY,
  ERROR_SPHINCSPLUS_ARGV,
  ERROR_SPHINCSPLUS_PARAMS,
  ERROR_SPHINCSPLUS_UNEXPECTED,
  ERROR_SPHINCSPLUS_LEAF_VERIFY,
};

static const char *PERSONAL_SCRIPT = "ckb-sphincs+-sct";
static const char *PERSONAL_MESSAGE = "ckb-sphincs+-msg";

#include <stdint.h>
#include <ckb_consts.h>
#include <ckb_syscall_apis.h>

static inline int _read_all(uint64_t fd, uint8_t *buffer, size_t length) {
  int err = CKB_SUCCESS;

  size_t read = 0;
  while (read < length) {
    size_t current_read = length - read;
    CHECK(ckb_read(fd, &buffer[read], &current_read));
    read += current_read;
  }

exit:
  return err;
}

static inline int _write_all(uint64_t fd, const uint8_t *buffer,
                             size_t length) {
  int err = CKB_SUCCESS;

  size_t written = 0;
  while (written < length) {
    size_t current_written = length - written;
    CHECK(ckb_write(fd, &buffer[written], &current_written));
    written += current_written;
  }

exit:
  return err;
}

#endif /* CKB_SPHINCSPLUS_COMMON_H */
