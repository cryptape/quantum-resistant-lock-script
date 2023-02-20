use ckb_script::TransactionScriptsVerifier;
use ckb_types::packed::Byte32;
use sphincsplus_rust::dummy_data_loader::DummyDataLoader;
use sphincsplus_rust::sphincsplus::CryptoType;
use sphincsplus_rust::utils::*;

pub fn debug_printer(_script: &Byte32, msg: &str) {
    print!("{}", msg);
}

pub const MAX_CYCLES: u64 = std::u64::MAX;

#[test]
fn test_base() {
    let hash_types = CryptoType::get_all();
    for hash_type in hash_types {
        let mut config = TestConfig::new(hash_type);

        let mut dummy = DummyDataLoader::new();

        let tx = gen_tx(&mut dummy, &mut config);
        let tx = sign_tx(&mut dummy, tx, &mut config);

        let resolved_tx = build_resolved_tx(&dummy, &tx);
        let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &dummy);

        verifier.set_debug_printer(debug_printer);
        let verify_result = verifier.verify(MAX_CYCLES);
        verify_result.expect("pass verification");
    }
}

#[test]
fn test_err_hash_type() {
    let mut config = TestConfig::new(CryptoType::ErrorHashMode);
    let mut dummy = DummyDataLoader::new();

    let tx = gen_tx(&mut dummy, &mut config);
    let tx = sign_tx(&mut dummy, tx, &mut config);

    let resolved_tx = build_resolved_tx(&dummy, &tx);
    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &dummy);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    if verify_result.is_ok() {
        panic!("pass verification");
    }
}

#[test]
fn test_err_sign() {
    let mut config = TestConfig::new(CryptoType::Shake256fRobust);
    config.sign_error = true;

    let mut dummy = DummyDataLoader::new();

    let tx = gen_tx(&mut dummy, &mut config);
    let tx = sign_tx(&mut dummy, tx, &mut config);

    let resolved_tx = build_resolved_tx(&dummy, &tx);
    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &dummy);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    if verify_result.is_ok() {
        panic!("pass verification");
    }
}

#[test]
fn test_err_pubkey() {
    let mut config = TestConfig::new(CryptoType::Shake256fRobust);
    config.pubkey_error = true;

    let mut dummy = DummyDataLoader::new();

    let tx = gen_tx(&mut dummy, &mut config);
    let tx = sign_tx(&mut dummy, tx, &mut config);

    let resolved_tx = build_resolved_tx(&dummy, &tx);
    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &dummy);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    if verify_result.is_ok() {
        panic!("pass verification");
    }
}

#[test]
fn test_err_message() {
    let mut config = TestConfig::new(CryptoType::Shake256fRobust);
    config.message_error = true;

    let mut dummy = DummyDataLoader::new();

    let tx = gen_tx(&mut dummy, &mut config);
    let tx = sign_tx(&mut dummy, tx, &mut config);

    let resolved_tx = build_resolved_tx(&dummy, &tx);
    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &dummy);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    if verify_result.is_ok() {
        panic!("pass verification");
    }
}
