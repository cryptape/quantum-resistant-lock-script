/*
 * Root lock calculates signing message hash, validates multisig
 * structure & logics, ensures multisig config hash is correctly calculated.
 *
 * It delegates to one of the leaf locks via exec or spawn syscalls to
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

#include <blake2b.h>
#include <ckb_syscalls.h>
#include <molecule/blockchain-api2.h>

#define CKB_SCRIPT_MERGE_TOOL_DEFINE_VARS
#include "params-finder.h"

#include "ckb_tx_message_all.h"
#include "witness_args_lazy_utils.h"
#include "zero_escape_encoding.h"

static uint32_t _load_script(uintptr_t arg[], uint8_t *ptr, uint32_t len,
                             uint32_t offset) {
  (void)arg;
  uint64_t output_len = len;
  int err = ckb_load_script(ptr, &output_len, offset);
  if (err != 0) {
    return 0;
  }
  if (output_len > len) {
    return len;
  } else {
    return (uint32_t)output_len;
  }
}

int extract_script(uint8_t *out_code_hash, uint8_t *out_hash_type,
                   uint8_t *multisig_hash) {
  int err = CKB_SUCCESS;

  uint8_t buffer[MOL2_DATA_SOURCE_LEN(SCRIPT_SIZE)];
  mol2_data_source_t *source_ptr = (mol2_data_source_t *)buffer;

  uint64_t length = SCRIPT_SIZE;
  CHECK(ckb_load_script(source_ptr->cache, &length, 0));

  source_ptr->read = _load_script;
  source_ptr->total_size = length;
  if (length > SCRIPT_SIZE) {
    source_ptr->cache_size = SCRIPT_SIZE;
  } else {
    source_ptr->cache_size = (uint32_t)length;
  }
  source_ptr->start_point = 0;
  source_ptr->max_cache_size = SCRIPT_SIZE;

  mol2_cursor_t cursor;
  cursor.offset = 0;
  cursor.size = (mol2_num_t)length;
  cursor.data_source = source_ptr;

  ScriptType script = make_Script(&cursor);

  mol2_cursor_t code_hash = script.t->code_hash(&script);
  CHECK2((code_hash.size == BLAKE2B_BLOCK_SIZE), ERROR_SPHINCSPLUS_ARGS);
  CHECK(mol2_read_and_advance(&code_hash, out_code_hash, BLAKE2B_BLOCK_SIZE));

  *out_hash_type = script.t->hash_type(&script);

  mol2_cursor_t args = script.t->args(&script);
  CHECK2((args.size == BLAKE2B_BLOCK_SIZE), ERROR_SPHINCSPLUS_ARGS);
  CHECK(mol2_read_and_advance(&args, multisig_hash, BLAKE2B_BLOCK_SIZE));

exit:
  return err;
}

static void init_blake2b_state(blake2b_state *state, const char *personal) {
  blake2b_param param;
  memset(&param, 0, sizeof(blake2b_param));

  param.digest_length = BLAKE2B_BLOCK_SIZE;
  param.fanout = 1;
  param.depth = 1;

  for (int i = 0; i < BLAKE2B_PERSONALBYTES; i++) {
    param.personal[i] = personal[i];
  }

  blake2b_init_param(state, &param);
}

static int write_to_blake2b(const uint8_t *data, size_t length, void *context) {
  blake2b_state *state = (blake2b_state *)context;
  blake2b_update(state, data, length);
  return 0;
}

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

enum PARAM_ID_UPDATE_STATE {
  PARAM_ID_STATE_UNSET = 0,
  PARAM_ID_STATE_SET,
  PARAM_ID_STATE_MULTIPLE,
};

int multisig_preliminary_check(WitnessArgsType *witness_args,
                               mol2_cursor_t *out_signatures,
                               uint8_t *actual_multisig_hash,
                               uint8_t *out_params_id) {
  int err = CKB_SUCCESS;

  blake2b_state s;
  init_blake2b_state(&s, PERSONAL_SCRIPT);

  BytesOptType lock = witness_args->t->lock(witness_args);
  CHECK2(!lock.t->is_none(&lock), ERROR_SPHINCSPLUS_WITNESS);

  mol2_cursor_t lock_bytes = lock.t->unwrap(&lock);

  uint8_t multisig_headers[4];
  CHECK(mol2_read_and_advance(&lock_bytes, multisig_headers, 4));

  mol2_cursor_t signatures = lock_bytes;

  CHECK2(multisig_headers[0] == MULTISIG_RESERVED_FIELD_VALUE,
         ERROR_SPHINCSPLUS_ENCODING);
  uint8_t require_first_n = multisig_headers[1];
  uint8_t threshold = multisig_headers[2];
  uint8_t pubkeys = multisig_headers[3];
  CHECK2(pubkeys > 0, ERROR_SPHINCSPLUS_ENCODING);
  CHECK2(threshold <= pubkeys, ERROR_SPHINCSPLUS_ENCODING);
  CHECK2(threshold > 0, ERROR_SPHINCSPLUS_ENCODING);
  CHECK2(require_first_n <= threshold, ERROR_SPHINCSPLUS_ENCODING);

  blake2b_update(&s, multisig_headers, 4);

  int last_param_id_state = PARAM_ID_STATE_UNSET;
  int last_param_id = 0;

  for (uint8_t i = 0; i < pubkeys; i++) {
    uint8_t id;
    CHECK(mol2_read_and_advance(&lock_bytes, &id, 1));
    uint8_t param_id = id & MULTISIG_PARAMS_ID_MASK;
    blake2b_update(&s, &param_id, 1);

    const CkbSphincsParams *params = NULL;
    CHECK(fetch_params(param_id, &params));

    uint8_t pubkey[params->pk_bytes];
    CHECK(mol2_read_and_advance(&lock_bytes, pubkey, params->pk_bytes));
    blake2b_update(&s, pubkey, params->pk_bytes);

    if ((id & MULTISIG_SIG_MASK) != 0) {
      mol2_advance(&lock_bytes, params->sign_bytes);

      CHECK2(threshold > 0, ERROR_SPHINCSPLUS_WITNESS);
      threshold--;
    } else {
      CHECK2(i >= require_first_n, ERROR_SPHINCSPLUS_WITNESS);
    }

    /*
     * This is actually a process to dedup param IDs from all
     * public keys, to see if all public keys use a single param
     * ID.
     */
    switch (last_param_id_state) {
      case PARAM_ID_STATE_UNSET: {
        last_param_id = param_id;
        last_param_id_state = PARAM_ID_STATE_SET;
      } break;
      case PARAM_ID_STATE_SET: {
        if (last_param_id != param_id) {
          last_param_id = 0;
          last_param_id_state = PARAM_ID_STATE_MULTIPLE;
        }
      } break;
      case PARAM_ID_STATE_MULTIPLE: {
        /* No-op here*/
      } break;
      default: {
        return ERROR_SPHINCSPLUS_UNEXPECTED;
      } break;
    }
  }

  CHECK2(threshold == 0, ERROR_SPHINCSPLUS_WITNESS);
  CHECK2(lock_bytes.size == 0, ERROR_SPHINCSPLUS_WITNESS);
  blake2b_final(&s, actual_multisig_hash, BLAKE2B_BLOCK_SIZE);
  *out_signatures = signatures;
  *out_params_id = last_param_id;

exit:
  return err;
}

int main(int argc, char *argv[]) {
  int err = CKB_SUCCESS;

  /* Extract current script's data first, so we can reclaim buffer set aside
   for loading script to be used later */
  uint8_t code_hash[BLAKE2B_BLOCK_SIZE];
  uint8_t hash_type;
  uint8_t expected_multisig_hash[BLAKE2B_BLOCK_SIZE];
  CHECK(extract_script(code_hash, &hash_type, expected_multisig_hash));

  /* The first witness in current script group contains signatures to validate
   */
  uint8_t witness_buffer[MOL2_DATA_SOURCE_LEN(MAX_WITNESS_SIZE)];
  WitnessArgsType witness_args;
  err = mol2_lazy_witness_args_load(witness_buffer, MAX_WITNESS_SIZE, 0,
                                    CKB_SOURCE_GROUP_INPUT, 1, &witness_args);
  CHECK2(err == 0, ERROR_SPHINCSPLUS_WITNESS);

  /* Preliminary validations on multisig configuration */
  uint8_t actual_multisig_hash[BLAKE2B_BLOCK_SIZE];
  mol2_cursor_t signatures;
  uint8_t dedup_param_id;
  CHECK(multisig_preliminary_check(&witness_args, &signatures,
                                   actual_multisig_hash, &dedup_param_id));
  CHECK2(memcmp(expected_multisig_hash, actual_multisig_hash,
                BLAKE2B_BLOCK_SIZE) == 0,
         ERROR_SPHINCSPLUS_MULTISIG_HASH);

  /*
   * CKB_TX_MESSAGE_ALL process, we will finalize the hash when preparing
   * args for exec / spawn.
   */
  blake2b_state s;
  init_blake2b_state(&s, PERSONAL_MESSAGE);
  err = ckb_tx_message_all_generate_with_witness_args(write_to_blake2b, &s,
                                                      &witness_args);
  CHECK2(err == 0, ERROR_SPHINCSPLUS_MESSAGE);

  /* Utilize exec or spawn for actual signature checks */
  if (dedup_param_id == 0) {
    /*
     * In case multiple param IDs are used, spawn will be used to create child
     * VMs for signature verification.
     */
    const CkbSphincsParams *all_params[CKB_SPHINCS_SUPPORTED_PARAMS_COUNT] = {
        NULL};
    uint64_t spawned_processes[CKB_SPHINCS_SUPPORTED_PARAMS_COUNT] = {0};
    uint64_t fds[CKB_SPHINCS_SUPPORTED_PARAMS_COUNT][2];

    /*
     * Spawn only use 1 byte header, 4 bytes of message length, and 34
     * bytes of actual message(empty FIPS 205 context) in argv. Remaining
     * are passed over via bytes.
     */
    uint8_t origin[1 + 4 + (2 + BLAKE2B_BLOCK_SIZE)];
    uint8_t escaped[sizeof(origin) * 2];

    origin[0] = 's';
    /* Empty FIPS 205 context */
    *((uint32_t *)&origin[1]) = 2 + BLAKE2B_BLOCK_SIZE;
    origin[1 + 4] = '\0';
    origin[1 + 4 + 1] = '\0';
    blake2b_final(&s, &origin[1 + 4 + 2], BLAKE2B_BLOCK_SIZE);
    size_t dst_length = sizeof(escaped);
    CHECK2(
        zero_escape_encode(origin, sizeof(origin), escaped, &dst_length) == 0,
        ERROR_SPHINCSPLUS_ENCODING);

    /*
     * Iterate over lock data again to verify each signature.
     */
    while (signatures.size > 0) {
      uint8_t header;
      CHECK(mol2_read_and_advance(&signatures, &header, 1));

      uint8_t param_id = header & MULTISIG_PARAMS_ID_MASK;
      if (all_params[param_id] == NULL) {
        CHECK(fetch_params(param_id, &all_params[param_id]));
      }
      uint32_t pk_size = all_params[param_id]->pk_bytes;
      uint32_t sign_size = all_params[param_id]->sign_bytes;
      CHECK2(pk_size + sign_size + 1 == (size_t)pk_size + (size_t)sign_size + 1,
             ERROR_SPHINCSPLUS_WITNESS;);

      if ((header & MULTISIG_SIG_MASK) != 0) {
        /*
         * Spawns a leaf process if needed, and use it to validate
         * the signature
         */
        CHECK2(signatures.size >= pk_size + sign_size,
               ERROR_SPHINCSPLUS_WITNESS);
        /* Spawn a new proces if needed */
        if (spawned_processes[param_id] == 0) {
          uint64_t root_to_leaf_fds[2];
          CHECK(ckb_pipe(root_to_leaf_fds));
          uint64_t leaf_to_root_fds[2];
          CHECK(ckb_pipe(leaf_to_root_fds));

          /*
           * Leaf process would read from root_to_leaf_fds[0],
           * and write to leaf_to_root_fds[1]
           */
          uint64_t inherited_fds[3] = {root_to_leaf_fds[0], leaf_to_root_fds[1],
                                       0};
          fds[param_id][0] = root_to_leaf_fds[1];
          fds[param_id][1] = leaf_to_root_fds[0];

          const char *argv[] = {(const char *)escaped};
          spawn_args_t spawn_args = {.argc = 1,
                                     .argv = (const char **)argv,
                                     .process_id = &spawned_processes[param_id],
                                     .inherited_fds = inherited_fds};
          CHECK(ckb_spawn_cell(code_hash, hash_type,
                               *all_params[param_id]->offset_ptr,
                               *all_params[param_id]->length_ptr, &spawn_args));
        }
        /* Sends data location to the leaf process */
        {
          uint8_t data[8 + 4 + 4 + 4];
          *((uint64_t *)&data[0]) = CKB_SOURCE_GROUP_INPUT;
          *((uint64_t *)&data[8]) = 0;
          *((uint64_t *)&data[8 + 4]) = signatures.offset - 1;
          *((uint64_t *)&data[8 + 4 + 4]) = 1 + pk_size + sign_size;

          CHECK(_write_all(fds[param_id][0], data, sizeof(data)));
        }
        /* Waits for leaf process to respond */
        {
          uint8_t response;
          CHECK(_read_all(fds[param_id][1], &response, 1));
          CHECK2(response == 0, ERROR_SPHINCSPLUS_LEAF_VERIFY);
        }
        /* Advance to the next signature if all the above succeeds */
        mol2_advance(&signatures, pk_size + sign_size);
      } else {
        /* Skip pubkey without a signature */
        CHECK2(signatures.size >= pk_size, ERROR_SPHINCSPLUS_WITNESS);
        mol2_advance(&signatures, pk_size);
      }
    }
  } else {
    /*
     * When a single param ID is used by all public keys in the multisig
     * configuration, we can use exec syscalls for fewer resource usage.
     */
    const CkbSphincsParams *params = NULL;
    CHECK(fetch_params(dedup_param_id, &params));

    /*
     * 1 byte header, 4 bytes of message length, 34 bytes of actual
     * message(empty FIPS 205 context is used here), 8 bytes of source,
     * 4 bytes of witness index, 4 bytes of offset within witness,
     * 4 bytes of actual process data length within witness.
     */
    uint8_t origin[1 + 4 + (2 + BLAKE2B_BLOCK_SIZE) + 8 + 4 + 4 + 4];
    uint8_t escaped[sizeof(origin) * 2 + 1];

    origin[0] = 'e';
    /* Empty FIPS 205 context */
    *((uint32_t *)&origin[1]) = 2 + BLAKE2B_BLOCK_SIZE;
    origin[1 + 4] = '\0';
    origin[1 + 4 + 1] = '\0';
    blake2b_final(&s, &origin[1 + 4 + 2], BLAKE2B_BLOCK_SIZE);
    *((uint64_t *)&origin[1 + 4 + (2 + BLAKE2B_BLOCK_SIZE)]) =
        CKB_SOURCE_GROUP_INPUT;
    *((uint32_t *)&origin[1 + 4 + (2 + BLAKE2B_BLOCK_SIZE) + 8]) = 0;
    *((uint32_t *)&origin[1 + 4 + (2 + BLAKE2B_BLOCK_SIZE) + 8 + 4]) =
        signatures.offset;
    *((uint32_t *)&origin[1 + 4 + (2 + BLAKE2B_BLOCK_SIZE) + 8 + 4 + 4]) =
        signatures.size;
    size_t dst_length = sizeof(escaped);
    CHECK2(
        zero_escape_encode(origin, sizeof(origin), escaped, &dst_length) == 0,
        ERROR_SPHINCSPLUS_ENCODING);

    char *argv[] = {(char *)escaped};
    CHECK(ckb_exec_cell(code_hash, hash_type, *params->offset_ptr,
                        *params->length_ptr, 1, (const char **)argv));
    ckb_exit(ERROR_SPHINCSPLUS_UNEXPECTED);
  }

exit:
  return err;
}
