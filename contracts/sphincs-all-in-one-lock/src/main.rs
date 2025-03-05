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
    ckb_tx_message_all_in_ckb_vm::generate_ckb_tx_message_all_with_witness,
    iterate_public_key_with_optional_signature,
    verifying::{lengths, verify},
    Hasher,
};
use ckb_gen_types::{packed::WitnessArgsReader, prelude::*};
use ckb_std::{ckb_constants::Source, high_level};

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

    let mut script_args_hasher = Hasher::script_args_hasher();
    script_args_hasher.update(&lock[0..4]);

    iterate_public_key_with_optional_signature(
        lock,
        |_i, param_id, sign_flag, public_key, signature| {
            script_args_hasher.update(&[sign_flag]);
            script_args_hasher.update(public_key);

            if let Some(signature) = signature {
                assert!(verify(param_id, public_key, signature, &message));
            }
        },
        lengths,
    );

    let actual_script_args_hash = script_args_hasher.hash();
    let current_script = high_level::load_script().expect("load script");
    assert_eq!(
        &current_script.args().raw_data(),
        &actual_script_args_hash[..]
    );

    0
}
