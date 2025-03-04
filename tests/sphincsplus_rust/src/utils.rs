use super::dummy_data_loader::DummyDataLoader;
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
use rand::prelude::{Rng, ThreadRng};
use rand::thread_rng;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

// The exact same Loader code from capsule's template, except that
// now we use MODE as the environment variable
const TEST_ENV_VAR: &str = "MODE";

pub enum TestEnv {
    Debug,
    Release,
}

impl FromStr for TestEnv {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "debug" => Ok(TestEnv::Debug),
            "release" => Ok(TestEnv::Release),
            _ => Err("no match"),
        }
    }
}

pub struct Loader(PathBuf);

impl Default for Loader {
    fn default() -> Self {
        let test_env = match env::var(TEST_ENV_VAR) {
            Ok(val) => val.parse().expect("test env"),
            Err(_) => TestEnv::Release,
        };
        Self::with_test_env(test_env)
    }
}

impl Loader {
    fn with_test_env(env: TestEnv) -> Self {
        let load_prefix = match env {
            TestEnv::Debug => "debug",
            TestEnv::Release => "release",
        };
        let mut base_path = match env::var("TOP") {
            Ok(val) => {
                let mut base_path: PathBuf = val.into();
                base_path.push("build");
                base_path
            }
            Err(_) => {
                let mut base_path = PathBuf::new();
                // cargo may use a different cwd when running tests, for example:
                // when running debug in vscode, it will use workspace root as cwd by default,
                // when running test by `cargo test`, it will use tests directory as cwd,
                // so we need a fallback path
                base_path.push("build");
                if !base_path.exists() {
                    base_path.pop();
                    base_path.push("..");
                    base_path.push("build");
                }
                base_path
            }
        };

        base_path.push(load_prefix);
        Loader(base_path)
    }

    pub fn load_binary(&self, name: &str) -> Bytes {
        let mut path = self.0.clone();
        path.push(name);
        let result = fs::read(&path);
        if result.is_err() {
            panic!("Binary {:?} is missing!", path);
        }
        result.unwrap().into()
    }
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

impl Default for TestConfig {
    fn default() -> Self {
        Self::new()
    }
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
        let mut buf = vec![0; len];

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

    pub fn single_sign_script_args(&self) -> Vec<u8> {
        let mut hasher = ckb_hash::Blake2bBuilder::new(32)
            .personal(b"ckb-sphincs+-sct")
            .build();
        hasher.update(&single_sign_script_args_prefix().expect("prefix"));
        hasher.update(&self.key.pk);
        let mut result = [0u8; 32];
        hasher.finalize(&mut result);
        result.to_vec()
    }
}

pub fn gen_tx(
    dummy: &mut DummyDataLoader,
    config: &mut TestConfig,
    name: &'static str,
) -> TransactionView {
    let lock_args = Bytes::from(if config.pubkey_hash_error {
        config.gen_rand_buf(32)
    } else {
        config.single_sign_script_args()
    });
    gen_tx_with_grouped_args(dummy, vec![(lock_args, 1)], config, name)
}

pub fn gen_tx_with_grouped_args(
    dummy: &mut DummyDataLoader,
    grouped_args: Vec<(Bytes, usize)>,
    config: &mut TestConfig,
    name: &'static str,
) -> TransactionView {
    let bin = Loader::default().load_binary(name);

    // setup sighash_all dep
    let sighash_all_out_point = {
        let contract_tx_hash = Byte32::from_slice(&config.gen_rand_buf(32)).unwrap();
        OutPoint::new(contract_tx_hash.clone(), 0)
    };
    // dep contract code
    let sighash_all_cell = CellOutput::new_builder()
        .capacity(Capacity::bytes(bin.len()).expect("script capacity").pack())
        .build();
    let sighash_all_cell_data_hash = CellOutput::calc_data_hash(&bin);
    dummy.cells.insert(
        sighash_all_out_point.clone(),
        (sighash_all_cell, bin.clone()),
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
    dummy: &DummyDataLoader,
    tx: TransactionView,
    begin_index: usize,
    len: usize,
    config: &mut TestConfig,
) -> TransactionView {
    let tx_hash = tx.hash();
    let sign_info_len = 5 + config.key.get_sign_len() + config.key.get_pk_len();

    let mut signed_witnesses: Vec<packed::Bytes> = tx
        .inputs()
        .into_iter()
        .enumerate()
        .map(|(i, _)| {
            if i == begin_index {
                let mut blake2b = ckb_hash::Blake2bBuilder::new(32)
                    .personal(b"ckb-sphincs+-msg")
                    .build();
                // CKB_TX_MESSAGE_ALL process, see: https://github.com/nervosnetwork/rfcs/pull/446
                blake2b.update(&tx_hash.raw_data());
                // digest input cells
                for cell_input in tx.inputs() {
                    let (cell_output, cell_data) = dummy
                        .cells
                        .get(&cell_input.previous_output())
                        .expect("fetch input cell");

                    blake2b.update(cell_output.as_slice());
                    blake2b.update(&(cell_data.len() as u32).to_le_bytes());
                    blake2b.update(cell_data);
                }
                // digest the first witness
                let witness = WitnessArgs::new_unchecked(tx.witnesses().get(i).unwrap().unpack());

                let zero_lock: Bytes = vec![0; sign_info_len].into();

                let witness_for_digest = witness
                    .clone()
                    .as_builder()
                    .lock(Some(zero_lock).pack())
                    .build();
                blake2b.update(
                    &(witness_for_digest.input_type().as_slice().len() as u32).to_le_bytes()[..],
                );
                blake2b.update(witness_for_digest.input_type().as_slice());
                blake2b.update(
                    &(witness_for_digest.output_type().as_slice().len() as u32).to_le_bytes()[..],
                );
                blake2b.update(witness_for_digest.output_type().as_slice());

                // digest the remaining witnesses
                ((i + 1)..(i + len)).for_each(|n| {
                    let witness = tx.witnesses().get(n).unwrap();
                    let witness_len = witness.raw_data().len() as u64;
                    blake2b.update(&witness_len.to_le_bytes());
                    blake2b.update(&witness.raw_data());
                });

                // The first 2 zero bytes denote empty FIPS 205 context
                let mut message = [0u8; 34];
                blake2b.finalize(&mut message[2..]);

                // fill in actual signature
                let witness_lock = {
                    if config.message_error {
                        config.rng.fill(&mut message[..]);
                    }
                    let start = std::time::Instant::now();
                    let mut witness_buf = vec![0; sign_info_len];

                    witness_buf[0..5].copy_from_slice(&single_sign_witness_prefix().unwrap());

                    witness_buf[5..config.key.get_pk_len() + 5].copy_from_slice(&if config
                        .pubkey_error
                    {
                        config.gen_rand_buf(config.key.get_pk_len())
                    } else {
                        config.key.pk.clone()
                    });

                    witness_buf[config.key.get_pk_len() + 5..].copy_from_slice(&if config
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

                    #[cfg(feature = "serialize_key")]
                    if config.print_sign {
                        use base64::prelude::*;
                        print!(
                            "--sign {}",
                            BASE64_STANDARD.encode(&witness_buf[config.key.get_pk_len() + 5..])
                        )
                    }

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
