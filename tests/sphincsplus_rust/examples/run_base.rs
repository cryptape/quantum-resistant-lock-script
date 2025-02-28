use ckb_script::TransactionScriptsVerifier;
use ckb_types::packed::Byte32;
use sphincsplus_rust_test::dummy_data_loader::DummyDataLoader;
use sphincsplus_rust_test::utils::*;

pub fn debug_printer(_script: &Byte32, msg: &str) {
    print!("{}", msg);
}

pub const MAX_CYCLES: u64 = std::u64::MAX;

fn main() {
    let mut config = TestConfig::new();
    config.print_time = true;

    let mut dummy = DummyDataLoader::new();

    let tx = gen_tx(&mut dummy, &mut config, "c-sphincs-all-in-one-lock");
    let tx = sign_tx(&mut dummy, tx, &mut config);

    let resolved_tx = build_resolved_tx(&dummy, &tx);
    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &dummy);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    let res = verify_result.expect("pass verification");
    println!("cycles: {} ({:.2?}M)", res, (res as f64) / 1024.0 / 1024.0);
}
