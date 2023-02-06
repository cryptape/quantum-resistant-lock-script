mod misc;

use ckb_script::TransactionScriptsVerifier;
use ckb_types::packed::Byte32;
use misc::*;
use sphincsplus_rust::dummy_data_loader::DummyDataLoader;

pub fn debug_printer(_script: &Byte32, msg: &str) {
    print!("{}", msg);
}

pub const MAX_CYCLES: u64 = std::u64::MAX;

#[test]
fn test_base() {
    let mut config = TestConfig::new();

    let mut dummy = DummyDataLoader::new();

    let tx = gen_tx(&mut dummy, &mut config);
    let tx = sign_tx(&mut dummy, tx, &mut config);

    let resolved_tx = build_resolved_tx(&dummy, &tx);
    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &dummy);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    let res = verify_result.expect("pass verification");
    println!("cycles: {}", res);
}
