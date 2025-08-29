#![no_main]

use libfuzzer_sys::fuzz_target;
use precise_fuzzing::run;

fuzz_target!(|data: &[u8]| {
    run(data);
});
