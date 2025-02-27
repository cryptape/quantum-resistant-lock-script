/*
 * This is a lock only used for testing against NIST test vectors.
 * Don't use it in production!
 *
 * It expects a variable length message in the first witness of the transaction
 * (not script group), the second witness of transaction should contain param
 * id, public key and signature.
 *
 * This format is purposely designed so we can pass each NIST test vector to a
 * CKB transaction to verify.
 *
 * It delegates to one of the leaf locks via exec syscalls to
 * do the actual sphincs+ signature verification.
 */

/*
 * The current project is architected so multiple C sources files
 * are compiled respectively. However, ckb-c-stdlib requires only
 * one C source file to include entry.h file. This trick here ensures
 * that only current source file will include entry.h, which also includes
 * all the libc implementations.
 */
#undef CKB_DECLARATION_ONLY
#include "entry.h"
#define CKB_DECLARATION_ONLY

#include "ckb-sphincsplus-common.h"

#include <ckb_syscalls.h>
#include <molecule/blockchain.h>

#define CKB_SCRIPT_MERGE_TOOL_DEFINE_VARS
#include "params-finder.h"

#include "zero_escape_encoding.h"

#define MAX_SCRIPT_SIZE (1024)
#undef MAX_WITNESS_SIZE
#define MAX_WITNESS_SIZE (512 * 1024)

int fetch_params(uint8_t id, const CkbSphincsParams **params) {
  int err = CKB_SUCCESS;
  id &= MULTISIG_PARAMS_ID_MASK;
  /* id uses offset by 1 */
  CHECK2(id >= 1 && id <= CKB_SPHINCS_SUPPORTED_PARAMS_COUNT,
         ERROR_SPHINCSPLUS_WITNESS);
  *params = &ckb_sphincs_supported_params[id - 1];

exit:
  return err;
}

int main() {
  int err = CKB_SUCCESS;

  /* First witness contains message in this case */
  uint8_t first_witness_data[MAX_WITNESS_SIZE];
  size_t first_witness_len = MAX_WITNESS_SIZE;
  err = ckb_load_witness(first_witness_data, &first_witness_len, 0, 0,
                         CKB_SOURCE_INPUT);
  /* We cannot use CHECK/CHECK2 yet due to variable length array initialization
   */
  if (err != 0) {
    return err;
  }
  if (first_witness_len > MAX_WITNESS_SIZE) {
    return ERROR_SPHINCSPLUS_WITNESS;
  }

  size_t message_len = (uint32_t)first_witness_len;
  uint8_t origin[1 + 4 + message_len + 8 + 4 + 4 + 4];
  uint8_t escaped[sizeof(origin) * 2];

  uint8_t second_witness_data[1];
  size_t second_witness_len = 1;
  CHECK(ckb_load_witness(second_witness_data, &second_witness_len, 0, 1,
                         CKB_SOURCE_INPUT));

  origin[0] = 'e';
  *((uint32_t *)&origin[1]) = message_len;
  memcpy(&origin[1 + 4], first_witness_data, message_len);
  *((uint64_t *)&origin[1 + 4 + message_len]) = CKB_SOURCE_INPUT;
  *((uint32_t *)&origin[1 + 4 + message_len + 8]) = 1;
  *((uint32_t *)&origin[1 + 4 + message_len + 8 + 4]) = 0;
  *((uint32_t *)&origin[1 + 4 + message_len + 8 + 4 + 4]) =
      (uint32_t)second_witness_len;
  size_t dst_length = sizeof(escaped);
  CHECK2(zero_escape_encode(origin, sizeof(origin), escaped, &dst_length) == 0,
         ERROR_SPHINCSPLUS_ENCODING);

  const CkbSphincsParams *params = NULL;
  CHECK(
      fetch_params(second_witness_data[0] & MULTISIG_PARAMS_ID_MASK, &params));

  uint8_t script_data[MAX_SCRIPT_SIZE];
  size_t script_len = MAX_SCRIPT_SIZE;
  CHECK(ckb_load_script(script_data, &script_len, 0));
  CHECK2(script_len <= MAX_SCRIPT_SIZE, ERROR_SPHINCSPLUS_ENCODING);
  mol_seg_t script_seg;
  script_seg.ptr = (uint8_t *)script_data;
  script_seg.size = script_len;

  mol_seg_t code_hash_seg = MolReader_Script_get_code_hash(&script_seg);
  mol_seg_t hash_type_seg = MolReader_Script_get_hash_type(&script_seg);

  char *argv[] = {(char *)escaped};
  CHECK(ckb_exec_cell(code_hash_seg.ptr, hash_type_seg.ptr[0],
                      *params->offset_ptr, *params->length_ptr, 1,
                      (const char **)argv));
  ckb_exit(ERROR_SPHINCSPLUS_UNEXPECTED);

exit:
  return err;
}
