mod sub_conversion;
mod sub_gen_key;
mod sub_sign;
mod utils;

use ckb_types::H256;
use clap::{arg, Command};
use std::path::PathBuf;
use utils::*;

fn get_args() -> Command {
    Command::new("")
        .about(&format!("For processing ckb-sphincs+ {}", get_hash()))
        .subcommand_required(true)
        .arg_required_else_help(true)
        .allow_external_subcommands(true)
        .subcommand(
            Command::new("gen-key")
                .about("Generate ckb-sphincs+ keypair")
                .arg(arg!(<KEY_FILE> "The keypair path"))
                .arg_required_else_help(true),
        )
        .subcommand(
            Command::new("signature")
                .about("Signature")
                .arg(arg!(--message <MESSAGE>))
                .arg(arg!(--key_file <KEY_FILE>))
                .arg_required_else_help(true),
        )
        .subcommand(
            Command::new("cc_to_sphincsplus")
                .about("conversion contract to sphincs+")
                .arg(arg!(--tx_hash <TX_HASH>))
                .arg(arg!(--tx_index <TX_INDEX>))
                .arg(arg!(--key_file <KEY_FILE>))
                .arg(arg!(--ckb_rpc <CKB_RPC>).default_value("http://127.0.0.1:8114"))
                .arg(arg!(--prikey <PRIKEY>))
                .arg_required_else_help(true),
        )
        .subcommand(
            Command::new("cc_to_secp")
                .about("conversion contract to default lock script")
                .arg(arg!(--tx_hash <TX_HASH>))
                .arg(arg!(--tx_index <TX_INDEX>))
                .arg(arg!(--key_file <KEY_FILE>))
                .arg(arg!(--ckb_rpc <CKB_RPC>).default_value("http://127.0.0.1:8114"))
                .arg(arg!(--lock_arg <LOCK_ARG>))
                .arg(arg!(--sp_tx_hash <LOCK_ARG> "SPHINCS+ Lock transaction hash"))
                .arg(arg!(--sp_tx_index <LOCK_ARG> "SPHINCS+ Lock transaction index"))
                .arg(arg!(--fee <FEE>).num_args(0..=usize::MAX))
                .arg_required_else_help(true),
        )
}

fn main() {
    let args = get_args();
    let matches = args.get_matches();

    match matches.subcommand() {
        Some(("gen-key", sub_matches)) => {
            let key_file = sub_matches.get_one::<String>("KEY_FILE").expect("required");
            sub_gen_key::subcmd_gen_key(PathBuf::from(key_file));
        }
        Some(("signature", sub_matches)) => {
            let key_file = sub_matches.get_one::<String>("key_file").expect("required");
            let message =
                H256::from_trimmed_str(sub_matches.get_one::<String>("message").expect("required"))
                    .unwrap();
            sub_sign::sub_sign(
                sub_gen_key::parse_key_file(PathBuf::from(key_file)),
                message,
            );
        }
        Some(("cc_to_sphincsplus", sub_matches)) => {
            let key_file = sub_matches.get_one::<String>("key_file").expect("required");
            let tx_hash = sub_matches.get_one::<String>("tx_hash").expect("required");
            let tx_index = sub_matches.get_one::<String>("tx_index").expect("required");
            let ckb_rpc = sub_matches.get_one::<String>("ckb_rpc").expect("required");
            let prikey = sub_matches.get_one::<String>("prikey").expect("required");

            sub_conversion::cc_to_sphincsplus(
                sub_gen_key::parse_key_file(PathBuf::from(key_file)),
                &ckb_rpc,
                H256::from_trimmed_str(tx_hash).unwrap(),
                tx_index.parse::<u32>().unwrap(),
                H256::from_trimmed_str(prikey).unwrap(),
            );
        }
        Some(("cc_to_secp", sub_matches)) => {
            let key_file = sub_matches.get_one::<String>("key_file").expect("required");
            let tx_hash = sub_matches.get_one::<String>("tx_hash").expect("required");
            let tx_index = sub_matches.get_one::<String>("tx_index").expect("required");
            let ckb_rpc = sub_matches.get_one::<String>("ckb_rpc").expect("required");
            let lock_arg = sub_matches.get_one::<String>("lock_arg").expect("required");
            let sp_tx_hash = sub_matches
                .get_one::<String>("sp_tx_hash")
                .expect("required");
            let sp_tx_index = sub_matches
                .get_one::<String>("sp_tx_index")
                .expect("required");
            let fee = sub_matches
                .get_one::<String>("fee")
                .expect("required")
                .parse::<u64>()
                .unwrap();

            sub_conversion::cc_to_def_lock_script(
                sub_gen_key::parse_key_file(PathBuf::from(key_file)),
                &ckb_rpc,
                H256::from_trimmed_str(tx_hash).unwrap(),
                tx_index.parse::<u32>().unwrap(),
                &str_to_bytes(&lock_arg),
                H256::from_trimmed_str(sp_tx_hash).unwrap(),
                sp_tx_index.parse::<u32>().unwrap(),
                fee.clone(),
            );
        }
        _ => panic!("Unknow subcommand: {:?}", matches.subcommand()),
    }
}
