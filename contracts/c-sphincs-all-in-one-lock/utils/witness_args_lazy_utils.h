#ifndef WITNESS_ARGS_LAZY_VALIDATOR_H_
#define WITNESS_ARGS_LAZY_VALIDATOR_H_

/*
 * This file provides utilities supporting lazy loading of WitnessArgs.
 * It contains:
 *
 * A hand-written validator for the WitnessArgs
 * structure based on lazy loader API defined here:
 * https://github.com/nervosnetwork/ckb-c-stdlib/blob/744c62e5259a5ab826e1a02ca36a811c9905f010/molecule/blockchain-api2.h
 * Ideally one should not manually write such a set of functions, but
 * instead rely on automatic code generations. But it could take a
 * while before we have such a thing. So we manually maintain a file here.
 *
 * Note that the implementation here will heavily depend on the internal
 * data structures defined in molecule-c2, for example, we shall peek directly
 * into cursor data structure. This is part of the reason we leverage lazy
 * reader to deal with the first witness in the C implementation, but choose
 * to load all data at once to memory in the Rust implementation.
 *
 * A utility function is also prepared that lazy-loads WitnessArgs into
 * a provided buffer. All boilerplate code for initializing data source
 * and cursor has been provided.
 */

#include <ckb_syscalls.h>
#include <molecule/blockchain-api2.h>

void mol2_advance(mol2_cursor_t *cursor, uint32_t len) {
  mol2_add_offset(cursor, len);
  mol2_sub_size(cursor, len);
}

int mol2_read_and_advance(mol2_cursor_t *cursor, uint8_t *buffer,
                          uint32_t read_len) {
  uint32_t out_len = mol2_read_at(cursor, buffer, read_len);
  if (out_len != read_len) {
    MOL2_PANIC(MOL2_ERR_DATA);
  }
  mol2_advance(cursor, read_len);

  return MOL2_OK;
}

mol2_errno mol2_lazy_fixvec_verify(const mol2_cursor_t *cursor,
                                   mol2_num_t item_size) {
  if (cursor->size < MOL2_NUM_T_SIZE) {
    return MOL2_ERR_HEADER;
  }
  mol2_num_t item_count = mol2_unpack_number(cursor);
  mol2_num_t items_size;
  if (__builtin_mul_overflow(item_size, item_count, &items_size)) {
    return MOL2_ERR_OVERFLOW;
  }
  mol2_num_t total_size;
  if (__builtin_add_overflow(MOL2_NUM_T_SIZE, items_size, &total_size)) {
    return MOL2_ERR_OVERFLOW;
  }
  if (cursor->size == total_size) {
    return MOL2_OK;
  } else {
    return MOL2_ERR_TOTAL_SIZE;
  }
}

mol2_errno mol2_lazy_bytes_verify(const BytesType *input, int compatible) {
  (void)compatible;
  return mol2_lazy_fixvec_verify(&input->cur, 1);
}

mol2_errno mol2_lazy_bytes_opt_verify(const BytesOptType *input,
                                      int compatible) {
  if (input->cur.size != 0) {
    mol2_cursor_t cursor = input->cur;
    BytesType inner = make_Bytes(&cursor);
    return mol2_lazy_bytes_verify(&inner, compatible);
  } else {
    return MOL2_OK;
  }
}

mol2_errno mol2_lazy_witness_args_verify(const WitnessArgsType *input,
                                         int compatible) {
  if (input->cur.size < MOL2_NUM_T_SIZE) {
    return MOL2_ERR_HEADER;
  }
  mol2_cursor_t ptr_cursor = input->cur;
  mol2_num_t total_size = mol2_unpack_number(&ptr_cursor);
  if (input->cur.size != total_size) {
    return MOL2_ERR_TOTAL_SIZE;
  }
  if (input->cur.size < MOL2_NUM_T_SIZE * 2) {
    return MOL2_ERR_HEADER;
  }
  mol2_advance(&ptr_cursor, MOL2_NUM_T_SIZE);

  mol2_num_t offset = mol2_unpack_number(&ptr_cursor);
  if (offset % 4 > 0 || offset < MOL2_NUM_T_SIZE * 2) {
    return MOL2_ERR_OFFSET;
  }
  mol2_num_t field_count = offset / MOL2_NUM_T_SIZE - 1;
  if (field_count < 3) {
    return MOL2_ERR_FIELD_COUNT;
  } else if ((!compatible) && field_count > 3) {
    return MOL2_ERR_FIELD_COUNT;
  }
  /* MOL2_NUM_T_SIZE * (field_count + 1) == offset */
  if (input->cur.size < MOL2_NUM_T_SIZE * (field_count + 1)) {
    return MOL2_ERR_HEADER;
  }

  mol2_num_t offsets[field_count + 1];
  offsets[0] = offset;
  for (mol2_num_t i = 1; i < field_count; i++) {
    mol2_advance(&ptr_cursor, MOL2_NUM_T_SIZE);

    offsets[i] = mol2_unpack_number(&ptr_cursor);
    if (offsets[i - 1] > offsets[i]) {
      return MOL2_ERR_OFFSET;
    }
  }
  if (offsets[field_count - 1] > total_size) {
    return MOL2_ERR_OFFSET;
  }
  offsets[field_count] = total_size;

  {
    mol2_cursor_t cursor = input->cur;
    mol2_add_offset(&cursor, offsets[0]);
    cursor.size = offsets[1] - offsets[0];
    BytesOptType lock = make_BytesOpt(&cursor);
    mol2_errno err = mol2_lazy_bytes_opt_verify(&lock, compatible);
    if (err != MOL2_OK) {
      return err;
    }
  }
  {
    mol2_cursor_t cursor = input->cur;
    mol2_add_offset(&cursor, offsets[1]);
    cursor.size = offsets[2] - offsets[1];
    BytesOptType input_type = make_BytesOpt(&cursor);
    mol2_errno err = mol2_lazy_bytes_opt_verify(&input_type, compatible);
    if (err != MOL2_OK) {
      return err;
    }
  }
  {
    mol2_cursor_t cursor = input->cur;
    mol2_add_offset(&cursor, offsets[2]);
    cursor.size = offsets[3] - offsets[2];
    BytesOptType output_type = make_BytesOpt(&cursor);
    mol2_errno err = mol2_lazy_bytes_opt_verify(&output_type, compatible);
    if (err != MOL2_OK) {
      return err;
    }
  }

  return MOL2_OK;
}

static uint32_t _mol2_read_from_witness(uintptr_t arg[], uint8_t *ptr,
                                        uint32_t len, uint32_t offset) {
  int err;
  uint64_t output_len = len;
  err = ckb_load_witness(ptr, &output_len, offset, arg[0], arg[1]);
  if (err != 0) {
    return 0;
  }
  if (output_len > len) {
    return len;
  } else {
    return (uint32_t)output_len;
  }
}

/*
 * Load a witness in WitnessArgs lazy reader format.
 *
 * +buffer+ must at least be of length MOL2_DATA_SOURCE_LEN(cache_size)
 */
int mol2_lazy_witness_args_load(uint8_t *buffer, size_t cache_size,
                                size_t index, size_t source, int validate,
                                WitnessArgsType *out) {
  mol2_data_source_t *source_ptr = (mol2_data_source_t *)buffer;

  uint64_t length = cache_size;
  int err = ckb_load_witness(source_ptr->cache, &length, 0, index, source);
  if (err != 0) {
    return err;
  }

  source_ptr->read = _mol2_read_from_witness;
  source_ptr->total_size = (uint32_t)length;
  source_ptr->args[0] = index;
  source_ptr->args[1] = source;
  if (length > cache_size) {
    source_ptr->cache_size = cache_size;
  } else {
    source_ptr->cache_size = (uint32_t)length;
  }
  source_ptr->start_point = 0;
  source_ptr->max_cache_size = cache_size;

  mol2_cursor_t cursor;
  cursor.offset = 0;
  cursor.size = (mol2_num_t)length;
  cursor.data_source = source_ptr;

  WitnessArgsType witness = make_WitnessArgs(&cursor);
  if (validate != 0) {
    err = mol2_lazy_witness_args_verify(&witness, 0);
    if (err != MOL2_OK) {
      mol2_printf(
          "WitnessArgs validation encounters failure, mol2 error code: %u\n",
          err);
      return err;
    }
  }

  if (out != NULL) {
    *out = witness;
  }

  return MOL2_OK;
}

#endif /* WITNESS_ARGS_LAZY_VALIDATOR_H_ */
