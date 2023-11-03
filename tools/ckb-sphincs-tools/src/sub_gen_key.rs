use serde_json::{from_str, Value};
use sphincsplus_rust_test::SphincsPlus;
use std::path::PathBuf;

pub fn subcmd_gen_key(key_file: PathBuf) {
    let key = SphincsPlus::new();
    let data = format!(
        "{{\n  \"pubkey\" : {:?},\n  \"prikey\" : {:?}\n}}",
        key.pk, key.sk
    );
    std::fs::write(key_file, data).expect("write keypair failed");

    println!("Generate key success");
}

pub fn parse_key_file(key_file: PathBuf) -> SphincsPlus {
    let data = String::from_utf8(std::fs::read(key_file).expect("Read key file failed")).unwrap();
    let v: Value = from_str(&data).unwrap();
    let pubkey: Vec<u8> = v["pubkey"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f.as_u64().unwrap() as u8)
        .collect();
    let prikey = v["prikey"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f.as_u64().unwrap() as u8)
        .collect();

    SphincsPlus {
        pk: pubkey,
        sk: prikey,
    }
}
