use ckb_sphincs_utils::SphincsPlus;
use sphincsplus_rust_test::dummy_data_loader::DummyDataLoader;
use sphincsplus_rust_test::utils::*;

fn main() {
    let key: SphincsPlus = SphincsPlus::new();
    print!("--key {} ", key.serialize_key());

    let mut config = TestConfig::new_with_key(key);
    config.print_sign = true;
    config.fixed_rand = true;

    let mut dummy = DummyDataLoader::new();

    let tx = gen_tx(&mut dummy, &mut config);
    sign_tx(&mut dummy, tx, &mut config);
}
