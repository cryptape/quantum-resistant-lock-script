use super::dummy_data_loader::DummyDataLoader;
use ckb_hash::blake2b_256;
use ckb_sphincs_utils::sphincsplus::*;
use ckb_types::core::{
    cell::{CellMetaBuilder, ResolvedTransaction},
    TransactionView,
};
use ckb_types::{
    bytes::Bytes,
    core::{Capacity, DepType, ScriptHashType, TransactionBuilder},
    packed::{
        self, Byte32, CellDep, CellInput, CellOutput, OutPoint, Script, WitnessArgs,
        WitnessArgsBuilder,
    },
    prelude::*,
};
use lazy_static::lazy_static;
use rand::prelude::{Rng, ThreadRng};
use rand::thread_rng;

lazy_static! {
    pub static ref SPHINCSPLUS_EXAMPLE_BIN: Bytes =
        Bytes::from(&include_bytes!("../../../build/sphincsplus_lock")[..]);
}

pub struct TestConfig {
    key: SphincsPlus,
    pub sign_error: bool,
    pub pubkey_hash_error: bool,
    pub pubkey_error: bool,
    pub message_error: bool,
    rng: ThreadRng,
    pub print_time: bool,
    pub print_sign: bool,
    pub fixed_rand: bool,
    rng_count: usize,
    pub sign: Option<Vec<u8>>,
}

impl TestConfig {
    pub fn new() -> Self {
        Self {
            key: SphincsPlus::new(),
            sign_error: false,
            pubkey_hash_error: false,
            pubkey_error: false,
            message_error: false,
            rng: thread_rng(),
            print_time: false,
            print_sign: false,
            fixed_rand: false,
            rng_count: 0,
            sign: None,
        }
    }

    #[cfg(feature = "serialize_key")]
    pub fn new_with_key(key: SphincsPlus) -> Self {
        Self {
            key,
            sign_error: false,
            pubkey_hash_error: false,
            pubkey_error: false,
            message_error: false,
            rng: thread_rng(),
            print_time: false,
            print_sign: false,
            fixed_rand: false,
            rng_count: 0,
            sign: None,
        }
    }

    pub fn gen_rand_buf(&mut self, len: usize) -> Vec<u8> {
        let mut buf = Vec::<u8>::with_capacity(len);
        buf.resize(len, 0);

        if !self.fixed_rand {
            self.rng.fill(buf.as_mut_slice());
        } else {
            for i in buf.iter_mut() {
                *i = self.rng_count as u8;
            }
            self.rng_count += 1;
        }
        buf
    }
}

pub fn gen_tx(dummy: &mut DummyDataLoader, config: &mut TestConfig) -> TransactionView {
    let lock_args = Bytes::from(if config.pubkey_hash_error {
        config.gen_rand_buf(32)
    } else {
        blake2b_256(&config.key.pk).to_vec()
    });
    gen_tx_with_grouped_args(dummy, vec![(lock_args, 1)], config)
}

pub fn gen_tx_with_grouped_args(
    dummy: &mut DummyDataLoader,
    grouped_args: Vec<(Bytes, usize)>,
    config: &mut TestConfig,
) -> TransactionView {
    // setup sighash_all dep
    let sighash_all_out_point = {
        let contract_tx_hash = Byte32::from_slice(&config.gen_rand_buf(32)).unwrap();
        OutPoint::new(contract_tx_hash.clone(), 0)
    };
    // dep contract code
    let sighash_all_cell = CellOutput::new_builder()
        .capacity(
            Capacity::bytes(SPHINCSPLUS_EXAMPLE_BIN.len())
                .expect("script capacity")
                .pack(),
        )
        .build();
    let sighash_all_cell_data_hash = CellOutput::calc_data_hash(&SPHINCSPLUS_EXAMPLE_BIN);
    dummy.cells.insert(
        sighash_all_out_point.clone(),
        (sighash_all_cell, SPHINCSPLUS_EXAMPLE_BIN.clone()),
    );

    // setup default tx builder
    let dummy_capacity = Capacity::shannons(42);
    let mut tx_builder = TransactionBuilder::default()
        .cell_dep(
            CellDep::new_builder()
                .out_point(sighash_all_out_point)
                .dep_type(DepType::Code.into())
                .build(),
        )
        .output_data(Bytes::new().pack());
    // validate_signature_rsa will be referenced by preimage in witness

    for (args, inputs_size) in grouped_args {
        // setup dummy input unlock script
        for _ in 0..inputs_size {
            let previous_tx_hash = Byte32::from_slice(&config.gen_rand_buf(32)).unwrap();
            let previous_out_point = OutPoint::new(previous_tx_hash, 0);
            let script = Script::new_builder()
                .args(args.pack())
                .code_hash(sighash_all_cell_data_hash.clone())
                .hash_type(ScriptHashType::Data1.into())
                .build();
            let previous_output_cell = CellOutput::new_builder()
                .capacity(dummy_capacity.pack())
                .lock(script);

            dummy.cells.insert(
                previous_out_point.clone(),
                (previous_output_cell.build(), Bytes::new()),
            );
            let witness_len = config.key.get_sign_len() + config.key.get_pk_len();
            let random_extra_witness = config.gen_rand_buf(witness_len);

            let witness_args = WitnessArgsBuilder::default()
                .lock(Some(Bytes::copy_from_slice(&random_extra_witness[..])).pack())
                .build();
            let since = 0;
            tx_builder = tx_builder
                .input(CellInput::new(previous_out_point, since))
                .witness(witness_args.as_bytes().pack());
        }
    }

    tx_builder.build()
}

pub fn sign_tx(
    dummy: &mut DummyDataLoader,
    tx: TransactionView,
    config: &mut TestConfig,
) -> TransactionView {
    let witness_len = tx.witnesses().len();
    sign_tx_by_input_group(dummy, tx, 0, witness_len, config)
}

pub fn sign_tx_by_input_group(
    _dummy: &mut DummyDataLoader,
    tx: TransactionView,
    begin_index: usize,
    len: usize,
    config: &mut TestConfig,
) -> TransactionView {
    let tx_hash = tx.hash();
    let sign_info_len = config.key.get_sign_len() + config.key.get_pk_len();

    let mut signed_witnesses: Vec<packed::Bytes> = tx
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
                    buf.resize(sign_info_len, 0);
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
                let witness_lock = {
                    if config.message_error {
                        config.rng.fill(&mut message);
                    }
                    let start = std::time::Instant::now();
                    let mut witness_buf = Vec::new();
                    witness_buf.resize(sign_info_len, 0);

                    witness_buf[..config.key.get_sign_len()].copy_from_slice(&if config
                        .sign
                        .is_none()
                    {
                        if config.sign_error {
                            config.gen_rand_buf(config.key.get_sign_len())
                        } else {
                            config.key.sign(&message).to_vec()
                        }
                    } else {
                        config.sign.as_ref().unwrap().to_vec()
                    });
                    if config.print_sign {
                        use base64::prelude::*;
                        print!(
                            "--sign {}",
                            BASE64_STANDARD.encode(&witness_buf[..config.key.get_sign_len()])
                        )
                    }

                    witness_buf[config.key.get_sign_len()..].copy_from_slice(
                        &if config.pubkey_error {
                            config.gen_rand_buf(config.key.get_pk_len())
                        } else {
                            config.key.pk.clone()
                        },
                    );

                    if config.print_time {
                        println!(
                            "sign time(native): {} us ({:.2?}s)",
                            start.elapsed().as_micros(),
                            start.elapsed().as_secs_f32()
                        );
                    }

                    Bytes::from(witness_buf)
                };

                witness
                    .as_builder()
                    .lock(Some(witness_lock).pack())
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

pub fn build_resolved_tx(
    data_loader: &DummyDataLoader,
    tx: &TransactionView,
) -> ResolvedTransaction {
    let resolved_cell_deps = tx
        .cell_deps()
        .into_iter()
        .map(|dep| {
            let deps_out_point = dep.clone();
            let (dep_output, dep_data) =
                data_loader.cells.get(&deps_out_point.out_point()).unwrap();
            CellMetaBuilder::from_cell_output(dep_output.to_owned(), dep_data.to_owned())
                .out_point(deps_out_point.out_point().clone())
                .build()
        })
        .collect();

    let mut resolved_inputs = Vec::new();
    for i in 0..tx.inputs().len() {
        let previous_out_point = tx.inputs().get(i).unwrap().previous_output();
        let (input_output, input_data) = data_loader.cells.get(&previous_out_point).unwrap();
        resolved_inputs.push(
            CellMetaBuilder::from_cell_output(input_output.to_owned(), input_data.to_owned())
                .out_point(previous_out_point)
                .build(),
        );
    }

    ResolvedTransaction {
        transaction: tx.clone(),
        resolved_cell_deps,
        resolved_inputs,
        resolved_dep_groups: vec![],
    }
}
