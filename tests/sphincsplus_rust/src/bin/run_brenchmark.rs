use ckb_script::TransactionScriptsVerifier;
use ckb_sphincs_utils::SphincsPlus;
use ckb_types::packed::Byte32;
use clap::{arg, Command};
use sphincsplus_rust_test::dummy_data_loader::DummyDataLoader;
use sphincsplus_rust_test::utils::*;

pub fn debug_printer(_script: &Byte32, msg: &str) {
    print!("{}", msg);
}

pub const MAX_CYCLES: u64 = std::u64::MAX;

fn main() {
    let args = Command::new("run brenchmark")
        .arg(arg!(--key <KEY> "sphincsplus keys"))
        .arg(arg!(--sign <SIGN> "sphincsplus sign"))
        .get_matches();
    let args_key = args.get_one::<String>("key").unwrap();

    use base64::prelude::*;
    let args_sign = BASE64_STANDARD
        .decode(args.get_one::<String>("sign").unwrap())
        .unwrap();

    let mut config = TestConfig::new_with_key(SphincsPlus::deserialize_key(args_key));
    config.print_time = true;
    config.fixed_rand = true;
    config.sign = Some(args_sign);

    let mut dummy = DummyDataLoader::new();

    let tx = gen_tx(&mut dummy, &mut config);
    let tx = sign_tx(&mut dummy, tx, &mut config);

    let resolved_tx = build_resolved_tx(&dummy, &tx);
    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &dummy);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    let res = verify_result.expect("pass verification");
    println!("cycles: {} ({:.2?}M)", res, (res as f64) / 1024.0 / 1024.0);
}
