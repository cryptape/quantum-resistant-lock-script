#![cfg_attr(not(any(feature = "native-simulator", test)), no_std)]
#![cfg_attr(not(test), no_main)]

#[cfg(any(feature = "native-simulator", test))]
extern crate alloc;

#[cfg(not(any(feature = "native-simulator", test)))]
ckb_std::entry!(program_entry);
#[cfg(not(any(feature = "native-simulator", test)))]
// By default, the following heap configuration is used:
// * 16KB fixed heap
// * 1.2MB(rounded up to be 16-byte aligned) dynamic heap
// * Minimal memory block in dynamic heap is 64 bytes
// For more details, please refer to ckb-std's default_alloc macro
// and the buddy-alloc alloc implementation.
ckb_std::default_alloc!(16384, 1258306, 64);

mod generated;

use crate::generated::params::{lengths, PARAM_IDS_COUNT};
use ckb_fips205_utils::{
    ckb_tx_message_all_in_ckb_vm::generate_ckb_tx_message_all_with_witness,
    iterate_public_key_with_optional_signature, Hasher, ParamId,
};
use ckb_gen_types::{core::ScriptHashType, packed::WitnessArgsReader, prelude::*};
use ckb_std::{ckb_constants::Source, high_level, syscalls};
use core::ffi::CStr;

enum ParsedParamId {
    NotSet,
    Single(ParamId),
    Multiple,
}

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

    let mut parsed_param_id = ParsedParamId::NotSet;

    iterate_public_key_with_optional_signature(
        lock,
        |_i, param_id, public_key, _signature| {
            script_args_hasher.update(&[param_id.into()]);
            script_args_hasher.update(public_key);

            match parsed_param_id {
                ParsedParamId::NotSet => {
                    parsed_param_id = ParsedParamId::Single(param_id);
                }
                ParsedParamId::Single(last_param_id) => {
                    if last_param_id != param_id {
                        parsed_param_id = ParsedParamId::Multiple;
                    }
                }
                ParsedParamId::Multiple => (),
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
    let cell_index = high_level::look_for_dep_with_hash2(
        &current_script.code_hash().raw_data(),
        if current_script.hash_type().as_slice()[0]
            == core::convert::Into::<u8>::into(ScriptHashType::Type)
        {
            ScriptHashType::Type
        } else {
            // It does not really matter which dataN is used
            ScriptHashType::Data2
        },
    )
    .expect("look for current script");

    match parsed_param_id {
        ParsedParamId::Single(param_id) => {
            // Replace current script with a leaf lock by param_id
            let mut escaped_buffer = [0u8; (1 + 4 + 34 + 8 + 4 + 4 + 4) * 2 + 1];
            let mut encoder = ZeroEncoder::new(&mut escaped_buffer);

            encoder.push(b'e');
            // Empty FIPS 205 context
            encoder.extend(&34u32.to_le_bytes()[..]);
            encoder.extend(&[0u8, 0u8]);
            encoder.extend(&message);
            encoder.extend(&(Source::GroupInput as u64).to_le_bytes()[..]);
            encoder.extend(&0u32.to_le_bytes()[..]);

            let offset: u32 = (lock[4..].as_ptr() as usize - first_witness_data.as_ptr() as usize)
                .try_into()
                .expect("overflow");
            encoder.extend(&offset.to_le_bytes()[..]);
            let length: u32 = (lock.len() - 4).try_into().expect("overflow");
            encoder.extend(&length.to_le_bytes()[..]);

            let (binary_offset, binary_length) = load_binary_infos(param_id);
            let bounds = ((binary_offset as u64) << 32) | (binary_length as u64);

            let return_code = syscalls::exec(
                cell_index,
                Source::CellDep,
                0,
                bounds as usize,
                &[CStr::from_bytes_with_nul(encoder.seal()).expect("create cstr")],
            );
            unreachable!("You should not see this return code: {}!", return_code);
        }
        ParsedParamId::Multiple => {
            // Iterate and spawn leaf locks on demand to verify signatures
            let mut escaped_buffer = [0u8; (1 + 4 + 34) * 2 + 1];
            let mut encoder = ZeroEncoder::new(&mut escaped_buffer);
            encoder.push(b's');
            // Empty FIPS 205 context
            encoder.extend(&34u32.to_le_bytes()[..]);
            encoder.extend(&[0u8, 0u8]);
            encoder.extend(&message);
            let spawn_argv0 = CStr::from_bytes_with_nul(encoder.seal()).expect("create cstr");

            let mut spawned_vms = [None; PARAM_IDS_COUNT];

            iterate_public_key_with_optional_signature(
                lock,
                |_i, param_id, public_key, signature| {
                    if let Some(signature) = signature {
                        let param_index = u8::from(param_id) as usize;
                        if spawned_vms[param_index].is_none() {
                            // Spawns a new VM for a param ID
                            let (binary_offset, binary_length) = load_binary_infos(param_id);
                            let bounds = ((binary_offset as u64) << 32) | (binary_length as u64);

                            let (root_to_leaf_fd0, root_to_leaf_fd1) =
                                syscalls::pipe().expect("pipe");
                            let (leaf_to_root_fd0, leaf_to_root_fd1) =
                                syscalls::pipe().expect("pipe");

                            let mut process_id: u64 = 0;
                            {
                                let argv = [spawn_argv0.as_ptr()];
                                let inherited_fds = [root_to_leaf_fd0, leaf_to_root_fd1, 0];
                                let mut spgs = syscalls::SpawnArgs {
                                    argc: 1,
                                    #[allow(clippy::unnecessary_cast)]
                                    argv: argv.as_ptr() as *const *const _,
                                    process_id: &mut process_id as *mut u64,
                                    inherited_fds: inherited_fds.as_ptr(),
                                };
                                syscalls::spawn(
                                    cell_index,
                                    Source::CellDep,
                                    0,
                                    bounds as usize,
                                    &mut spgs,
                                )
                                .expect("spawn");
                            }
                            spawned_vms[param_index] = Some((root_to_leaf_fd1, leaf_to_root_fd0));
                        }

                        let (root_to_leaf_fd, leaf_to_root_fd) = spawned_vms[param_index].unwrap();
                        // Writes data to verify to child VM
                        {
                            let mut data = [0u8; 8 + 4 + 4 + 4];
                            data[0..8]
                                .copy_from_slice(&(Source::GroupInput as u64).to_le_bytes()[..]);

                            let offset: u32 = (public_key.as_ptr() as u64
                                - first_witness_data.as_ptr() as u64
                                - 1)
                            .try_into()
                            .expect("overflow");
                            data[8 + 4..8 + 4 + 4].copy_from_slice(&offset.to_le_bytes());
                            let length: u32 = (1 + public_key.len() + signature.len())
                                .try_into()
                                .expect("overflow");
                            data[8 + 4 + 4..].copy_from_slice(&length.to_le_bytes());

                            let mut written = 0;
                            while written < data.len() {
                                let current_written =
                                    syscalls::write(root_to_leaf_fd, &data[written..])
                                        .expect("write");
                                written += current_written;
                            }
                        }
                        // Reads reasponse from child VM
                        {
                            let mut response = [0u8; 1];

                            let mut read = 0;
                            while read < response.len() {
                                let current_read =
                                    syscalls::read(leaf_to_root_fd, &mut response[read..])
                                        .expect("read");
                                read += current_read;
                            }

                            assert_eq!(response[0], 0);
                        }
                    }
                },
                lengths,
            );
        }
        ParsedParamId::NotSet => unreachable!(),
    }

    0
}

pub struct ZeroEncoder<'a> {
    i: usize,
    buf: &'a mut [u8],
}

impl<'a> ZeroEncoder<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { i: 0, buf }
    }

    pub fn push(&mut self, v: u8) {
        if v == 0 || v == 0xFE {
            self.buf[self.i] = 0xFE;
            self.buf[self.i + 1] = v.wrapping_sub(1);
            self.i += 2;
        } else {
            self.buf[self.i] = v;
            self.i += 1;
        }
    }

    pub fn extend(&mut self, data: &[u8]) {
        for v in data {
            self.push(*v);
        }
    }

    pub fn seal(self) -> &'a [u8] {
        self.buf[self.i] = 0;
        &self.buf[0..=self.i]
    }
}

fn load_binary_infos(param_id: ParamId) -> (u32, u32) {
    let (p1, p2) = crate::generated::params::binary_infos(param_id);
    unsafe { (*p1, *p2) }
}
