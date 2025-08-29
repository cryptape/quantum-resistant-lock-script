use afl::fuzz;
use precise_fuzzing::run;

fn main() {
    loop {
        fuzz!(|data: &[u8]| {
            run(data);
        });
    }
}
