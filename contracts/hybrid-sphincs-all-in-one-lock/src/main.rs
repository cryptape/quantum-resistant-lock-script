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

use crate::generated::params::{indices, lengths, PARAM_IDS_COUNT};
use ckb_fips205_utils::{
    ckb_tx_message_all_in_ckb_vm::generate_ckb_tx_message_all_with_witness,
    iterate_public_key_with_optional_signature, Hasher, ParamId,
};
use ckb_gen_types::{core::ScriptHashType, packed::WitnessArgsReader, prelude::*};
use ckb_std::{
    assert_eq,
    asserts::{expect_result, unwrap_option},
    ckb_constants::Source,
    env::argv,
    high_level, syscalls,
};
use core::ffi::CStr;

enum ParsedParamId {
    NotSet,
    Single(ParamId),
    Multiple,
}

#[repr(i8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Error {
    Syscall = 71,
    CkbTxMessageAll,
    LockMissing,
    SphincsplusVerify,
    ScriptArgsMismatch,
    Overflow,
    PipeCreationFailure,
    SpawnFailure,
    IOFailure,
    Argv,
}

impl From<Error> for i8 {
    fn from(e: Error) -> i8 {
        e as i8
    }
}

pub fn program_entry() -> i8 {
    // Unfortunately, till lazy reader with validator mode is coming, we will
    // have to stick with this. Fortunately, all data in the first witness will
    // be loaded one way or another. What we really pay here, is merely (*cough*)
    // ~600K memory space.
    let first_witness_data = expect_result(
        Error::Syscall,
        high_level::load_witness(0, Source::GroupInput),
        "load witness",
    );

    let mut message_hasher = Hasher::message_hasher();
    expect_result(
        Error::CkbTxMessageAll,
        generate_ckb_tx_message_all_with_witness(&mut message_hasher, &first_witness_data),
        "ckb tx message all",
    );
    let message = message_hasher.hash();

    // The first witness is already validated to be in correct format
    let first_witness = WitnessArgsReader::new_unchecked(&first_witness_data);
    let lock = unwrap_option(Error::LockMissing, first_witness.lock().to_opt()).raw_data();

    let mut script_args_hasher = Hasher::script_args_hasher();
    script_args_hasher.update(&lock[0..4]);

    let mut parsed_param_id = ParsedParamId::NotSet;

    iterate_public_key_with_optional_signature(
        lock,
        |_i, param_id, sign_flag, public_key, _signature| {
            script_args_hasher.update(&[sign_flag]);
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
    let current_script = expect_result(Error::Syscall, high_level::load_script(), "load script");
    assert_eq!(
        Error::ScriptArgsMismatch,
        &current_script.args().raw_data(),
        &actual_script_args_hash[..]
    );
    let cell_index = if let Some(argv0) = argv().first() {
        let mut argv0 = argv0.to_bytes().to_vec();
        let decoded = unwrap_option(Error::Argv, zero_decode_in_place(&mut argv0));
        assert_eq!(Error::Argv, decoded.len(), 8);
        u64::from_le_bytes(decoded.try_into().unwrap()) as usize
    } else {
        expect_result(
            Error::Syscall,
            high_level::look_for_dep_with_hash2(
                &current_script.code_hash().raw_data(),
                if current_script.hash_type().as_slice()[0]
                    == core::convert::Into::<u8>::into(ScriptHashType::Type)
                {
                    ScriptHashType::Type
                } else {
                    // It does not really matter which dataN is used
                    ScriptHashType::Data2
                },
            ),
            "look for current script",
        )
    };

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

            let offset: u32 = expect_result(
                Error::Overflow,
                (lock[4..].as_ptr() as usize - first_witness_data.as_ptr() as usize).try_into(),
                "overflow",
            );
            encoder.extend(&offset.to_le_bytes()[..]);
            let length: u32 =
                expect_result(Error::Overflow, (lock.len() - 4).try_into(), "overflow");
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
                |_i, param_id, _sign_flag, public_key, signature| {
                    if let Some(signature) = signature {
                        let param_index = indices(param_id);
                        if spawned_vms[param_index].is_none() {
                            // Spawns a new VM for a param ID
                            let (binary_offset, binary_length) = load_binary_infos(param_id);
                            let bounds = ((binary_offset as u64) << 32) | (binary_length as u64);

                            let (root_to_leaf_fd0, root_to_leaf_fd1) =
                                expect_result(Error::PipeCreationFailure, syscalls::pipe(), "pipe");
                            let (leaf_to_root_fd0, leaf_to_root_fd1) =
                                expect_result(Error::PipeCreationFailure, syscalls::pipe(), "pipe");

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
                                expect_result(
                                    Error::SpawnFailure,
                                    syscalls::spawn(
                                        cell_index,
                                        Source::CellDep,
                                        0,
                                        bounds as usize,
                                        &mut spgs,
                                    ),
                                    "spawn",
                                );
                            }
                            spawned_vms[param_index] = Some((root_to_leaf_fd1, leaf_to_root_fd0));
                        }

                        let (root_to_leaf_fd, leaf_to_root_fd) = spawned_vms[param_index].unwrap();
                        // Writes data to verify to child VM
                        {
                            let mut data = [0u8; 3 + 8 + 4 + 4 + 4];
                            // ckb-script-ipc compatible headers
                            data[0] = 0; // Version in VLQ encoding
                            data[1] = 1; // Method ID in VLQ encoding
                            data[2] = 20; // Length in VLQ encoding
                            data[3..3 + 8]
                                .copy_from_slice(&(Source::GroupInput as u64).to_le_bytes()[..]);

                            let offset: u32 = expect_result(
                                Error::Overflow,
                                (public_key.as_ptr() as u64
                                    - first_witness_data.as_ptr() as u64
                                    - 1)
                                .try_into(),
                                "overflow",
                            );
                            data[3 + 8 + 4..3 + 8 + 4 + 4].copy_from_slice(&offset.to_le_bytes());
                            let length: u32 = expect_result(
                                Error::Overflow,
                                (1 + public_key.len() + signature.len()).try_into(),
                                "overflow",
                            );
                            data[3 + 8 + 4 + 4..].copy_from_slice(&length.to_le_bytes());

                            let mut written = 0;
                            while written < data.len() {
                                let current_written = expect_result(
                                    Error::IOFailure,
                                    syscalls::write(root_to_leaf_fd, &data[written..]),
                                    "write",
                                );
                                written += current_written;
                            }
                        }
                        // Reads reasponse from child VM
                        {
                            let mut response = [0u8; 3];

                            let mut read = 0;
                            while read < response.len() {
                                let current_read = expect_result(
                                    Error::IOFailure,
                                    syscalls::read(leaf_to_root_fd, &mut response[read..]),
                                    "read",
                                );
                                read += current_read;
                            }

                            assert_eq!(Error::SphincsplusVerify, response[0], 0);
                            assert_eq!(Error::SphincsplusVerify, response[1], 0);
                            assert_eq!(Error::SphincsplusVerify, response[2], 0);
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

pub fn zero_decode_in_place(buf: &mut [u8]) -> Option<&[u8]> {
    let mut wrote = 0;
    let mut i = 0;

    while i < buf.len() {
        if buf[i] == 0xFE {
            if i + 1 >= buf.len() {
                return None;
            }
            buf[wrote] = buf[i + 1].wrapping_add(1);
            wrote += 1;
            i += 2;
        } else {
            buf[wrote] = buf[i];
            wrote += 1;
            i += 1;
        }
    }

    Some(&buf[0..wrote])
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
