#![cfg_attr(not(any(feature = "library", test)), no_std)]
#![cfg_attr(not(test), no_main)]

#[cfg(any(feature = "library", test))]
extern crate alloc;

#[cfg(not(any(feature = "library", test)))]
ckb_std::entry!(program_entry);
#[cfg(not(any(feature = "library", test)))]
// By default, the following heap configuration is used:
// * 16KB fixed heap
// * 1.2MB(rounded up to be 16-byte aligned) dynamic heap
// * Minimal memory block in dynamic heap is 64 bytes
// For more details, please refer to ckb-std's default_alloc macro
// and the buddy-alloc alloc implementation.
ckb_std::default_alloc!(16384, 1258306, 64);

use alloc::{vec, vec::Vec};
use ckb_std::{
    ckb_constants::Source,
    high_level,
    syscalls::{self, SpawnArgs},
};
use core::ffi::CStr;

pub fn program_entry() -> i8 {
    let args = high_level::load_witness(1, Source::Input).expect("load arg witness");
    let args_s = core::str::from_utf8(&args).expect("cast arg witness to utf8");

    let cell_dep_index = zero_encode(&1u64.to_le_bytes());
    let argv0 = CStr::from_bytes_with_nul(&cell_dep_index).expect("create argv0");

    match args_s {
        "exec" => {
            assert_eq!(0, syscalls::exec(1, Source::CellDep, 0, 0, &[argv0]));
        }
        "spawn" => {
            let inherited_fds = [0u64];
            let mut process_id = u64::MAX;
            let argv = [argv0.as_ptr() as *const _];
            let mut spawn_args = SpawnArgs {
                argc: argv.len() as u64,
                argv: argv.as_ptr(),
                process_id: &mut process_id as *mut _,
                inherited_fds: inherited_fds.as_ptr(),
            };
            syscalls::spawn(1, Source::CellDep, 0, 0, &mut spawn_args).expect("spawn");
            let exit_code = syscalls::wait(process_id).expect("wait");
            assert_eq!(0, exit_code);
        }
        _ => panic!("Unknown arg witness: {args_s}"),
    }

    0
}

pub fn zero_encode(src: &[u8]) -> Vec<u8> {
    let mut buf = vec![0; src.len() * 2];
    let mut encoder = ZeroEncoder::new(&mut buf);
    encoder.extend(src);
    encoder.seal().to_vec()
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
