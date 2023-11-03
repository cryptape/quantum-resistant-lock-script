use super::utils::*;
use ckb_crypto::secp::Privkey;
use ckb_hash::blake2b_256;
use ckb_jsonrpc_types as json_types;
use ckb_jsonrpc_types::Either;
use ckb_sdk::rpc::CkbRpcClient;
use ckb_types::{
    bytes::Bytes,
    core::{Capacity, DepType, ScriptHashType, TransactionBuilder, TransactionView},
    packed::{
        Byte32, CellDep, CellInput, CellOutput, OutPoint, Script, WitnessArgs, WitnessArgsBuilder,
    },
    prelude::*,
    H256,
};
use lazy_static::lazy_static;
use sphincsplus_rust_test::SphincsPlus;

lazy_static! {
    pub static ref SPHINCSPLUS_EXAMPLE_BIN: Bytes =
        Bytes::from(&include_bytes!("../../../build/sphincsplus_lock")[..]);
}

pub const SIGNATURE_SIZE: usize = 65;

fn get_secp256k1_sighash(ckb_client: &mut CkbRpcClient) -> CellDep {
    let genesis_scripts = ckb_client
        .get_block_by_number(0.into())
        .expect("get genesis scripts failed")
        .expect("genesis scripts is empty");

    let tx = genesis_scripts.transactions.get(1).unwrap();

    CellDep::new_builder()
        .out_point(OutPoint::new(
            Byte32::from_slice(tx.hash.as_bytes()).unwrap(),
            0 as u32,
        ))
        .dep_type(DepType::DepGroup.into())
        .build()
}

fn _get_sphincsplus_sighash(ckb_client: &mut CkbRpcClient, sp_tx_hash: H256, sp_tx_index: u32) {
    let sp_tx_index = sp_tx_index as usize;
    let tx = ckb_client.get_transaction(sp_tx_hash);
    let tx = tx.unwrap();
    let tx = tx.unwrap();
    let tx = tx.transaction;
    let tx = tx.unwrap();
    let tx = tx.inner;

    let data = match tx {
        Either::Left(txx) => txx.inner.outputs_data[sp_tx_index].clone(),
        Either::Right(_txx) => {
            panic!("unsupport")
        }
    };

    let msg = blake2b_256(data.as_bytes());
    println!("sphincs hash: {:02x?}", msg);
}

fn get_sphincsplus_code_hash() -> [u8; 32] {
    blake2b_256(&SPHINCSPLUS_EXAMPLE_BIN.to_vec())
}

pub fn sign_tx(tx: TransactionView, key: &Privkey) -> TransactionView {
    let witnesses_len = tx.witnesses().len();
    sign_tx_by_input_group(tx, key, 0, witnesses_len)
}

pub fn sign_tx_by_input_group(
    tx: TransactionView,
    key: &Privkey,
    begin_index: usize,
    len: usize,
) -> TransactionView {
    let tx_hash = tx.hash();
    let mut signed_witnesses: Vec<ckb_types::packed::Bytes> = tx
        .inputs()
        .into_iter()
        .enumerate()
        .map(|(i, _)| {
            if i == begin_index {
                let mut blake2b = ckb_hash::new_blake2b();
                let mut message = [0u8; 32];
                blake2b.update(&tx_hash.raw_data());
                // digest the first witness
                let witness = WitnessArgs::new_unchecked(tx.witnesses().get(i).unwrap().unpack());
                let zero_lock: Bytes = {
                    let mut buf = Vec::new();
                    buf.resize(SIGNATURE_SIZE, 0);
                    buf.into()
                };
                let witness_for_digest = witness
                    .clone()
                    .as_builder()
                    .lock(Some(zero_lock).pack())
                    .build();
                let witness_len = witness_for_digest.as_bytes().len() as u64;
                blake2b.update(&witness_len.to_le_bytes());
                blake2b.update(&witness_for_digest.as_bytes());
                ((i + 1)..(i + len)).for_each(|n| {
                    let witness = tx.witnesses().get(n).unwrap();
                    let witness_len = witness.raw_data().len() as u64;
                    blake2b.update(&witness_len.to_le_bytes());
                    blake2b.update(&witness.raw_data());
                });
                blake2b.finalize(&mut message);
                let message = H256::from(message);
                let sig = key.sign_recoverable(&message).expect("sign");
                witness
                    .as_builder()
                    .lock(Some(Bytes::from(sig.serialize())).pack())
                    .build()
                    .as_bytes()
                    .pack()
            } else {
                tx.witnesses().get(i).unwrap_or_default()
            }
        })
        .collect();
    for i in signed_witnesses.len()..tx.witnesses().len() {
        signed_witnesses.push(tx.witnesses().get(i).unwrap());
    }
    // calculate message
    tx.as_advanced_builder()
        .set_witnesses(signed_witnesses)
        .build()
}

pub fn sign_tx_sphincs_plus(tx: TransactionView, key: &SphincsPlus) -> TransactionView {
    let witnesses_len = tx.witnesses().len();
    sign_tx_by_input_group_sphincs_plus(tx, key, 0, witnesses_len)
}

pub fn sign_tx_by_input_group_sphincs_plus(
    tx: TransactionView,
    key: &SphincsPlus,
    begin_index: usize,
    len: usize,
) -> TransactionView {
    let tx_hash = tx.hash();
    let mut signed_witnesses: Vec<ckb_types::packed::Bytes> = tx
        .inputs()
        .into_iter()
        .enumerate()
        .map(|(i, _)| {
            if i == begin_index {
                let mut blake2b = ckb_hash::new_blake2b();
                let mut message = [0u8; 32];
                blake2b.update(&tx_hash.raw_data());
                // digest the first witness
                let witness = WitnessArgs::new_unchecked(tx.witnesses().get(i).unwrap().unpack());
                let zero_lock: Bytes = {
                    let mut buf = Vec::new();
                    buf.resize(key.get_sign_len() + key.get_pk_len(), 0);
                    buf.into()
                };
                let witness_for_digest = witness
                    .clone()
                    .as_builder()
                    .lock(Some(zero_lock).pack())
                    .build();
                let witness_len = witness_for_digest.as_bytes().len() as u64;
                blake2b.update(&witness_len.to_le_bytes());
                blake2b.update(&witness_for_digest.as_bytes());
                ((i + 1)..(i + len)).for_each(|n| {
                    let witness = tx.witnesses().get(n).unwrap();
                    let witness_len = witness.raw_data().len() as u64;
                    blake2b.update(&witness_len.to_le_bytes());
                    blake2b.update(&witness.raw_data());
                });
                blake2b.finalize(&mut message);
                let message = H256::from(message);

                let witness_data = {
                    let mut data = Vec::<u8>::new();
                    data.resize(key.get_sign_len() + key.get_pk_len(), 0);

                    data[..key.get_sign_len()].copy_from_slice(&key.sign(message.as_bytes()));
                    data[key.get_sign_len()..].copy_from_slice(&key.pk);

                    Bytes::from(data)
                };

                witness
                    .as_builder()
                    .lock(Some(witness_data).pack())
                    .build()
                    .as_bytes()
                    .pack()
            } else {
                tx.witnesses().get(i).unwrap_or_default()
            }
        })
        .collect();
    for i in signed_witnesses.len()..tx.witnesses().len() {
        signed_witnesses.push(tx.witnesses().get(i).unwrap());
    }
    // calculate message
    tx.as_advanced_builder()
        .set_witnesses(signed_witnesses)
        .build()
}

pub fn cc_to_sphincsplus(
    key: SphincsPlus,
    ckb_rpc: &str,
    tx_hash: H256,
    tx_index: u32,
    prikey: H256,
) {
    let mut ckb_client = CkbRpcClient::new(ckb_rpc);

    let input_tx = ckb_client
        .get_transaction(tx_hash.clone())
        .expect("get input transaction failed");
    assert!(input_tx.is_some(), "input transaction is empty");
    let input_tx = input_tx
        .unwrap()
        .transaction
        .expect("input transaction is empty");

    let input_cell = {
        let tx = input_tx.inner;
        match tx {
            Either::Left(tx_view) => tx_view
                .inner
                .outputs
                .get(tx_index as usize)
                .expect("input index invade")
                .clone(),
            Either::Right(_json_byte) => {
                panic!("unsupport")
            }
        }
    };

    let tx_builder = TransactionBuilder::default();
    let out_point = OutPoint::new_builder()
        .tx_hash(tx_hash.pack())
        .index(tx_index.pack())
        .build();

    let witness_data = Bytes::copy_from_slice(&[0u8; 32]);
    let witness_args = WitnessArgsBuilder::default()
        .lock(Some(witness_data).pack())
        .build();

    let mut tx_builder = tx_builder
        .cell_dep(
            CellDep::new_builder()
                .out_point(out_point.clone())
                .dep_type(DepType::Code.into())
                .build(),
        )
        .cell_dep(get_secp256k1_sighash(&mut ckb_client))
        .input(CellInput::new(out_point, 0))
        .witness(witness_args.as_bytes().pack());

    // output cell
    let output_script = Script::new_builder()
        .args(Bytes::from(blake2b_256(&key.pk).to_vec()).pack())
        .code_hash(Byte32::from_slice(&get_sphincsplus_code_hash()).unwrap())
        .hash_type(ScriptHashType::Data1.into())
        .build();
    let capacity = input_cell.capacity.value() / 100000000;
    let fee = (capacity / 1024 + 1) * 1000;
    let output_capacity = Capacity::shannons((input_cell.capacity.value() - fee) as u64);
    tx_builder = tx_builder
        .output(
            CellOutput::new_builder()
                .lock(output_script.clone())
                .capacity(output_capacity.pack())
                .build(),
        )
        .output_data(Bytes::new().pack());

    let priv_key = Privkey::from(prikey);

    let tx = tx_builder.build();
    let tx = sign_tx(tx, &priv_key);

    println!("tx hash: {:?}", tx.hash());
    let outputs_validator = Some(json_types::OutputsValidator::Passthrough);
    let tx = json_types::TransactionView::from(tx);

    println!("{}", serde_json::to_string(&tx.inner).unwrap());

    ckb_client
        .send_transaction(tx.inner, outputs_validator)
        .expect("send transaction failed");
}

pub fn cc_to_def_lock_script(
    key: SphincsPlus,
    ckb_rpc: &str,
    tx_hash: H256,
    tx_index: u32,
    lock_arg: &[u8],
    sp_tx_hash: H256,
    sp_tx_index: u32,
    fee: u64,
) {
    let mut ckb_client = CkbRpcClient::new(ckb_rpc);

    // get_sphincsplus_sighash(&mut ckb_client, sp_tx_hash.clone(), sp_tx_index.clone());

    let input_tx = ckb_client
        .get_transaction(tx_hash.clone())
        .expect("get input transaction failed");
    assert!(input_tx.is_some(), "input transaction is empty");
    let input_tx = input_tx
        .unwrap()
        .transaction
        .expect("input transaction is empty");

    let input_cell = {
        let tx = input_tx.inner;
        match tx {
            Either::Left(tx_view) => tx_view
                .inner
                .outputs
                .get(tx_index as usize)
                .expect("input index invade")
                .clone(),
            Either::Right(_json_byte) => {
                panic!("unsupport")
            }
        }
    };

    let tx_builder = TransactionBuilder::default();
    let out_point = OutPoint::new_builder()
        .tx_hash(tx_hash.pack())
        .index(tx_index.pack())
        .build();

    let witness_len = key.get_sign_len() + key.get_pk_len();
    let witness_data = Bytes::from({
        let mut b = Vec::<u8>::new();
        b.resize(witness_len, 0);
        b
    });

    let witness_args = WitnessArgsBuilder::default()
        .lock(Some(witness_data).pack())
        .build();

    let input_lock_dep = CellDep::new_builder()
        .out_point(OutPoint::new(
            Byte32::from_slice(sp_tx_hash.as_bytes()).unwrap(),
            sp_tx_index,
        ))
        .dep_type(DepType::Code.into())
        .build();

    let mut tx_builder = tx_builder
        .cell_dep(
            CellDep::new_builder()
                .out_point(out_point.clone())
                .dep_type(DepType::Code.into())
                .build(),
        )
        .cell_dep(input_lock_dep)
        .input(CellInput::new(out_point, 0))
        .witness(witness_args.as_bytes().pack());

    // output cell
    let output_script = Script::new_builder()
        .args(Bytes::from(lock_arg.to_vec()).pack())
        .code_hash(
            Byte32::from_slice(&str_to_bytes(
                "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
            ))
            .unwrap(),
        )
        .hash_type(ScriptHashType::Type.into())
        .build();

    let capacity = input_cell.capacity.value() / 100000000;

    println!("Capacity: {}, Need fee: {}", capacity, fee);
    let output_capacity = Capacity::shannons((input_cell.capacity.value() - fee) as u64);
    tx_builder = tx_builder
        .output(
            CellOutput::new_builder()
                .lock(output_script.clone())
                .capacity(output_capacity.pack())
                .build(),
        )
        .output_data(Bytes::new().pack());

    let tx = tx_builder.build();
    let tx = sign_tx_sphincs_plus(tx, &key);

    println!("tx hash: {:?}", tx.hash());
    let outputs_validator = Some(json_types::OutputsValidator::Passthrough);
    let tx = json_types::TransactionView::from(tx);

    println!("{}", serde_json::to_string(&tx.inner).unwrap());

    ckb_client
        .send_transaction(tx.inner, outputs_validator)
        .expect("send transaction failed");
}
