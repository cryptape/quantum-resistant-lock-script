#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]

#[cfg(test)]
extern crate alloc;

#[cfg(not(test))]
ckb_std::entry!(program_entry);
#[cfg(not(test))]
// By default, the following heap configuration is used:
// * 16KB fixed heap
// * 1.2MB(rounded up to be 16-byte aligned) dynamic heap
// * Minimal memory block in dynamic heap is 64 bytes
// For more details, please refer to ckb-std's default_alloc macro
// and the buddy-alloc alloc implementation.
ckb_std::default_alloc!(16384, 1258306, 64);

use ckb_fips205_utils::{
    ckb_tx_message_all_in_ckb_vm::generate_ckb_tx_message_all_with_witness, lengths, verify,
    Hasher, ParamId,
};
use ckb_gen_types::{packed::WitnessArgsReader, prelude::*};
use ckb_std::{ckb_constants::Source, high_level};

const MULTISIG_RESERVED_FIELD_VALUE: u8 = 0x80;
const MULTISIG_PARAMS_ID_MASK: u8 = 0x7F;
const MULTISIG_SIG_MASK: u8 = 1u8 << 7;

pub fn program_entry() -> i8 {
    // Unfortunately, till lazy reader with validator mode is coming, we will
    // have to stick with this. Fortunately, all data in the first witness will
    // be loaded one way or another. What we really pay here, is merely (*cough*)
    // ~600K memory space.
    let first_witness_data = high_level::load_witness(0, Source::GroupInput).expect("load witness");

    let mut message_hasher = Hasher::message_hasher();
    generate_ckb_tx_message_all_with_witness(&mut message_hasher, &first_witness_data)
        .expect("ckb tx message all");
    let message = message_hasher.hash();

    // The first witness is already validated to be in correct format
    let first_witness = WitnessArgsReader::new_unchecked(&first_witness_data);
    let lock = first_witness.lock().to_opt().unwrap().raw_data();

    assert!(lock.len() > 4);
    assert_eq!(lock[0], MULTISIG_RESERVED_FIELD_VALUE);
    let require_first_n = lock[1];
    let mut threshold = lock[2];
    let pubkeys = lock[3];
    assert!(pubkeys > 0);
    assert!(threshold <= pubkeys);
    assert!(threshold > 0);
    assert!(require_first_n <= threshold);

    let mut script_args_hasher = Hasher::script_args_hasher();
    script_args_hasher.update(&lock[0..4]);

    let mut i = 4;
    for pubkey_index in 0..pubkeys {
        let id = lock[i];
        let param_id: ParamId = (id & MULTISIG_PARAMS_ID_MASK)
            .try_into()
            .expect("parse param id");
        script_args_hasher.update(&[param_id.into()]);

        let (public_key_length, signature_length) = lengths(param_id);
        let public_key = &lock[i + 1..i + 1 + public_key_length];
        script_args_hasher.update(public_key);

        if (id & MULTISIG_SIG_MASK) != 0 {
            let signature =
                &lock[i + 1 + public_key_length..i + 1 + public_key_length + signature_length];
            assert!(verify(param_id, public_key, signature, &message));

            assert!(threshold > 0);
            threshold -= 1;
            i += 1 + public_key_length + signature_length;
        } else {
            assert!(pubkey_index >= require_first_n);
            i += 1 + public_key_length;
        }
    }

    assert!(threshold == 0);
    assert!(i == lock.len());

    let actual_script_args_hash = script_args_hasher.hash();
    let current_script = high_level::load_script().expect("load script");
    assert_eq!(
        &current_script.args().raw_data(),
        &actual_script_args_hash[..]
    );

    0
}
