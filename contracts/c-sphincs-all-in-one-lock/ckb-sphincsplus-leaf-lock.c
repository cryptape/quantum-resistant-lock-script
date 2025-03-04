/*
 * Leaf lock takes calculated message hash, together with a range in
 * witness as input. It runs sphincs+ signature verifications based on
 * data included in witness.
 *
 * Notice the leaf locks only handle sphincs+ signature verifications,
 * it knows nothing about CKB transaction structure, other than the fact
 * that a series of public keys & signatures are kept in one witness structure.
 * It does not even know if the witness is in molecule formats or not.
 * All it accepts is an offset & length in witness to load data from.
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

/* Sphincs public APIs */
#include "api.h"
/* Glue code between CKB-VM environment, and sphincs reference impl. */
#include "ckb-sphincsplus.h"
#include "zero_escape_encoding.h"
/* We only use molecule-c2's cursor here for minimal code size. */
#include "witness_args_lazy_utils.h"

#define ITERATION_SIZE (1 + SPHINCS_PLUS_PK_SIZE + SPHINCS_PLUS_SIGN_SIZE)
#define MAX_BATCH_BUFFER_SIZE (256 * 1024)
#define BATCH_COUNT (MAX_BATCH_BUFFER_SIZE / ITERATION_SIZE)
#define BATCH_BUFFER_SIZE (ITERATION_SIZE * BATCH_COUNT)

int verify(const uint8_t *message, size_t message_length,
           mol2_cursor_t data_cursor) {
  int err = CKB_SUCCESS;

  while (data_cursor.size > 0) {
    uint8_t param_id;
    CHECK(mol2_read_and_advance(&data_cursor, &param_id, 1));

    CHECK2((param_id & MULTISIG_PARAMS_ID_MASK) == PARAMS_ID,
           ERROR_SPHINCSPLUS_PARAMS);

    if ((param_id & MULTISIG_SIG_MASK) != 0) {
      /* Validate a signature when we see one */
      CHECK2(data_cursor.size >= SPHINCS_PLUS_PK_SIZE + SPHINCS_PLUS_SIGN_SIZE,
             ERROR_SPHINCSPLUS_WITNESS);

      uint8_t pubkey[SPHINCS_PLUS_PK_SIZE];
      uint8_t sign[SPHINCS_PLUS_SIGN_SIZE];

      CHECK(mol2_read_and_advance(&data_cursor, pubkey, SPHINCS_PLUS_PK_SIZE));
      CHECK(mol2_read_and_advance(&data_cursor, sign, SPHINCS_PLUS_SIGN_SIZE));

      err = sphincs_plus_verify(sign, SPHINCS_PLUS_SIGN_SIZE, message,
                                message_length, pubkey, SPHINCS_PLUS_PK_SIZE);
      CHECK2(err == 0, ERROR_SPHINCSPLUS_VERIFY);
    } else {
      /* Skip pubkey without a signature */
      CHECK2(data_cursor.size >= SPHINCS_PLUS_PK_SIZE,
             ERROR_SPHINCSPLUS_WITNESS);
      mol2_advance(&data_cursor, SPHINCS_PLUS_PK_SIZE);
    }
  }

exit:
  return err;
}

/*
 * +buffer+ must have length of `MOL2_DATA_SOURCE_LEN(BATCH_BUFFER_SIZE)`,
 * +data+ must have length of 20, which contains:
 * * little-endian uint64_t denoting witness source
 * * little-endian uint32_t denoting witenss index
 * * little-endian uint32_t denoting data offset within witness
 * * little-endian uint32_t denoting data length in witness
 */
mol2_cursor_t _build_cursor_from_data(uint8_t *buffer, const uint8_t *data) {
  uint64_t source = *((const uint64_t *)&data[0]);
  uint32_t index = *((const uint32_t *)&data[8]);
  uint32_t offset = *((const uint32_t *)&data[8 + 4]);
  uint32_t length = *((const uint32_t *)&data[8 + 4 + 4]);

  mol2_data_source_t *source_ptr = (mol2_data_source_t *)buffer;

  source_ptr->read = _mol2_read_from_witness;
  source_ptr->total_size = (uint64_t)offset + (uint64_t)length;
  source_ptr->args[0] = index;
  source_ptr->args[1] = source;
  source_ptr->cache_size = 0;
  source_ptr->start_point = 0;
  source_ptr->max_cache_size = BATCH_BUFFER_SIZE;

  mol2_cursor_t cursor;
  cursor.offset = offset;
  cursor.size = length;
  cursor.data_source = source_ptr;

  return cursor;
}

int handle_exec(const uint8_t *command, size_t command_length) {
  int err = CKB_SUCCESS;
  uint8_t buffer[MOL2_DATA_SOURCE_LEN(BATCH_BUFFER_SIZE)];

  /*
   * 'e' is followed by the following data:
   * * little-endian uint32_t denoting message length
   * * message data of variable length,
   * * 20 bytes of data that can be used to build cursor from witness
   * * data to verify, see +_build_cursor_from_data+ function for more
   * details.
   */
  CHECK2(command_length >= 1 + 4 + 8 + 4 + 4 + 4, ERROR_SPHINCSPLUS_ARGV);
  uint32_t message_length = *((uint32_t *)&command[1]);
  CHECK2(command_length == 1 + 4 + message_length + 8 + 4 + 4 + 4,
         ERROR_SPHINCSPLUS_ARGV);
  const uint8_t *message = &command[1 + 4];

  mol2_cursor_t cursor =
      _build_cursor_from_data(buffer, &command[1 + 4 + message_length]);
  CHECK(verify(message, message_length, cursor));

exit:
  return err;
}

int handle_spawn(const uint8_t *command, size_t command_length) {
  int err = CKB_SUCCESS;
  uint8_t buffer[MOL2_DATA_SOURCE_LEN(BATCH_BUFFER_SIZE)];

  /*
   * 's' is followed by the following data:
   * * little-endian uint32_t denoting message length
   * * message data of variable length,
   *
   * Witness data to verify will be passed over via pipes.
   */
  CHECK2(command_length >= 1 + 4, ERROR_SPHINCSPLUS_ARGV);
  uint32_t message_length = *((uint32_t *)&command[1]);
  CHECK2(command_length == 1 + 4 + message_length, ERROR_SPHINCSPLUS_ARGV);
  const uint8_t *message = &command[1 + 4];

  uint64_t fds[2];
  size_t fds_length = 2;
  CHECK(ckb_inherited_fds(fds, &fds_length));
  CHECK2(fds_length == 2, ERROR_SPHINCSPLUS_ARGV);

  uint64_t root_to_leaf_fd = fds[0];
  uint64_t leaf_to_root_fd = fds[1];

  while (1) {
    uint8_t data[3 + 8 + 4 + 4 + 4];
    CHECK(_read_all(root_to_leaf_fd, data, sizeof(data)));
    /* ckb-script-ipc compatible headers in VLQ encoding. */
    CHECK2(data[0] == 0, ERROR_SPHINCSPLUS_ARGV);
    CHECK2(data[1] == 1, ERROR_SPHINCSPLUS_ARGV);
    CHECK2(data[2] == 20, ERROR_SPHINCSPLUS_ARGV);

    mol2_cursor_t cursor = _build_cursor_from_data(buffer, &data[3]);
    int verify_err = verify(message, message_length, cursor);
    if (verify_err != 0) {
      /*
       * Signature verification encounters an error, the following
       * steps are performed:
       *
       * 1. A non-zero response is write to root
       * 2. Both fds are closed
       * 3. Current script terminates with non-zero exit code
       */
      uint8_t failure_response = 1;
      CHECK(_write_all(leaf_to_root_fd, &failure_response, 1));
      CHECK(ckb_close(root_to_leaf_fd));
      CHECK(ckb_close(leaf_to_root_fd));
      return verify_err;
    } else {
      uint8_t success_response = 0;
      CHECK(_write_all(leaf_to_root_fd, &success_response, 1));
    }
  }

exit:
  return err;
}

int main(int argc, char *argv[]) {
  int err = CKB_SUCCESS;

  CHECK2(argc == 1, ERROR_SPHINCSPLUS_ARGV);
  /* Decode argv[0] for arguments passed by exec/spawn syscalls */
  size_t length = 0;
  CHECK2(zero_escape_decode_cstring_in_place(argv[0], &length) == 0,
         ERROR_SPHINCSPLUS_ARGV);
  uint8_t *command = (uint8_t *)argv[0];
  switch (command[0]) {
    case 'e': {
      CHECK(handle_exec(command, length));
    } break;
    case 's': {
      CHECK(handle_spawn(command, length));
    } break;
    default: {
      return ERROR_SPHINCSPLUS_ARGV;
    } break;
  }

exit:
  return err;
}
