use ckb_types::H256;
use sphincsplus_rust_test::SphincsPlus;

pub fn sub_sign(key: SphincsPlus, message: H256) {
    let sign = key.sign(message.as_bytes());
    println!("{:?}", sign);
}
