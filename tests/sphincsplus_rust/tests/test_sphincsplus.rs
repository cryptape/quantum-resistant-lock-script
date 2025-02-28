use ckb_script::TransactionScriptsVerifier;
use ckb_types::packed::Byte32;
use sphincsplus_rust_test::dummy_data_loader::DummyDataLoader;
use sphincsplus_rust_test::utils::*;

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
    verify_result.expect("pass verification");
}

#[test]
fn test_err_sign() {
    let mut config = TestConfig::new();
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
fn test_err_pubkey_hash() {
    let mut config = TestConfig::new();
    config.pubkey_hash_error = true;

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
    let mut config = TestConfig::new();
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
    let mut config = TestConfig::new();
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

#[test]
fn test_pubkey_and_signature_lengths() {
    let param_id: ckb_fips205_utils::ParamId = ckb_sphincs_utils::sphincsplus::param_id()
        .expect("param id must exist")
        .try_into()
        .expect("parse param id");
    let (pubkey_length, signature_length) = ckb_fips205_utils::lengths(param_id);

    let key = ckb_sphincs_utils::SphincsPlus::default();
    assert_eq!(key.get_pk_len(), pubkey_length);
    assert_eq!(key.get_sign_len(), signature_length);
}
