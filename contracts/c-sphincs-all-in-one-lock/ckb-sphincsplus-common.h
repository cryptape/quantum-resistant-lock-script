#ifndef CKB_SPHINCSPLUS_COMMON_H
#define CKB_SPHINCSPLUS_COMMON_H

/*
 * Common definitions shared by CKB sphincs+ locks
 */

#define BLAKE2B_BLOCK_SIZE 32
#define ONE_BATCH_SIZE 1024 * 64
#define MAX_WITNESS_SIZE ONE_BATCH_SIZE
#define SCRIPT_SIZE ONE_BATCH_SIZE

#define MULTISIG_RESERVED_FIELD_MASK 0x80
#define MULTISIG_RESERVED_FIELD_VALUE 0x80
#define MULTISIG_PARAMS_ID_MASK 0xF
#define MULTISIG_SIG_MASK (1 << 7)

#ifndef MOL2_EXIT
#define MOL2_EXIT ckb_exit
#endif

#undef ASSERT
// #define ASSERT(s)
#define ASSERT(s) ckb_exit(-1)

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
  ERROR_SPHINCSPLUS_MESSAGE,
  ERROR_SPHINCSPLUS_ENCODING,
  ERROR_SPHINCSPLUS_ARGS,
  ERROR_SPHINCSPLUS_MULTISIG_HASH,
  ERROR_SPHINCSPLUS_WITNESS,
  ERROR_SPHINCSPLUS_VERIFY,
  ERROR_SPHINCSPLUS_ARGV,
  ERROR_SPHINCSPLUS_PARAMS,
  ERROR_SPHINCSPLUS_UNEXPECTED,
};

static const char *PERSONAL_SCRIPT = "ckb-sphincs+-sct";
static const char *PERSONAL_MESSAGE = "ckb-sphincs+-msg";

#endif /* CKB_SPHINCSPLUS_COMMON_H */
