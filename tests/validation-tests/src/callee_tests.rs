use crate::Loader;
use ckb_fips205_utils::signing::*;
use ckb_testtool::{
    ckb_types::{
        bytes::Bytes,
        core::{TransactionBuilder, TransactionView},
        packed::*,
        prelude::*,
    },
    context::Context,
};
use proptest::prelude::*;
use rand::{rngs::StdRng, Rng, SeedableRng};
use rand_core::CryptoRngCore;
use std::path::Path;

const C_NAME: &str = "c-sphincs-all-in-one-lock";
const HYBRID_NAME: &str = "hybrid-sphincs-all-in-one-lock";
const RUST_NAME: &str = "sphincs-all-in-one-lock";
const TEST_RUNNER: &str = "spawn-exec-test-runner";

// We are only testing a few parameter sets here, since the affected
// code actually has nothing to do with sphincsplus parameters.

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 10, .. ProptestConfig::default()
    })]

    #[test]
    fn test_spawn_c_sha2_128f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Sha2128F::new(&mut rng);
        _test_valid_tx(C_NAME, signer, rng, "spawn");
    }

    #[test]
    fn test_exec_c_sha2_128f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Sha2128F::new(&mut rng);
        _test_valid_tx(C_NAME, signer, rng, "exec");
    }

    #[test]
    fn test_spawn_hybrid_sha2_128f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Sha2128F::new(&mut rng);
        _test_valid_tx(HYBRID_NAME, signer, rng, "spawn");
    }

    #[test]
    fn test_exec_hybrid_sha2_128f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Sha2128F::new(&mut rng);
        _test_valid_tx(HYBRID_NAME, signer, rng, "exec");
    }

    #[test]
    fn test_spawn_rust_sha2_128f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Sha2128F::new(&mut rng);
        _test_valid_tx(RUST_NAME, signer, rng, "spawn");
    }

    #[test]
    fn test_exec_rust_sha2_128f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Sha2128F::new(&mut rng);
        _test_valid_tx(RUST_NAME, signer, rng, "exec");
    }

    #[test]
    fn test_spawn_c_shake_256s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Shake256S::new(&mut rng);
        _test_valid_tx(C_NAME, signer, rng, "spawn");
    }

    #[test]
    fn test_exec_c_shake_256s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Shake256S::new(&mut rng);
        _test_valid_tx(C_NAME, signer, rng, "exec");
    }

    #[test]
    fn test_spawn_hybrid_shake_256s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Shake256S::new(&mut rng);
        _test_valid_tx(HYBRID_NAME, signer, rng, "spawn");
    }

    #[test]
    fn test_exec_hybrid_shake_256s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Shake256S::new(&mut rng);
        _test_valid_tx(HYBRID_NAME, signer, rng, "exec");
    }

    #[test]
    fn test_spawn_rust_shake_256s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Shake256S::new(&mut rng);
        _test_valid_tx(RUST_NAME, signer, rng, "spawn");
    }

    #[test]
    fn test_exec_rust_shake_256s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Shake256S::new(&mut rng);
        _test_valid_tx(RUST_NAME, signer, rng, "exec");
    }
}

fn _save_tx_if_requested(context: &Context, tx: &TransactionView) {
    if let Some(path) = std::env::var_os("DUMP_TXS_PATH") {
        if let Ok(s) = std::env::var("DUMP_PROBABILITY") {
            let prob = u16::from_str_radix(&s, 10).expect("parse dump probability");
            if prob > 256 {
                panic!("DUMP_PROBABILITY can only range from 0 to 256!");
            }
            let val = tx.hash().nth0().as_slice()[0] as u16;
            if val < prob {
                let directory = Path::new(&path);
                std::fs::create_dir_all(directory).expect("mkdir -p");

                let path = directory.join(format!("0x{:x}.json", tx.hash()));
                let mock_tx = context.dump_tx(tx).expect("dump failed tx");
                let json = serde_json::to_string_pretty(&mock_tx).expect("json");
                std::fs::write(path, json).expect("write");
            }
        }
    }
}

fn _test_valid_tx<S: TxSigner, R: Rng + CryptoRngCore>(
    name: &'static str,
    signer: S,
    rng: R,
    additional_witness_arg: &str,
) {
    let (context, tx) = _build_valid_tx(name, signer, rng, additional_witness_arg);

    _save_tx_if_requested(&context, &tx);

    let cycles = context
        .verify_tx(&tx, 200_000_000)
        .expect("pass verification");
    println!("consume cycles: {cycles}");
}

fn _build_valid_tx<S: TxSigner, R: Rng + CryptoRngCore>(
    name: &'static str,
    signer: S,
    mut rng: R,
    additional_witness_arg: &str,
) -> (Context, TransactionView) {
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary(TEST_RUNNER);
    let out_point = context.deploy_cell(contract_bin);

    let quantum_bin: Bytes = Loader::default().load_binary(name);
    let quantum_out_point = context.deploy_cell(quantum_bin);

    let lock_script = context
        .build_script(&out_point, signer.script_args())
        .expect("script");

    let input_cell_data = gen_data(&mut rng, 1, 1000);
    let input_cell_output = CellOutput::new_builder()
        .capacity((2000u64 * 100000000u64).pack())
        .lock(lock_script.clone())
        .build();
    let input_out_point = context.create_cell(input_cell_output.clone(), input_cell_data.clone());
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();

    let output_cell_data = gen_data(&mut rng, 1, 1000);
    let output_cell_output = CellOutput::new_builder()
        .capacity((1999u64 * 100000000u64).pack())
        .lock(lock_script.clone())
        .build();

    let witness_args = WitnessArgs::new_builder()
        .input_type(Some(gen_data(&mut rng, 1, 200)).pack())
        .output_type(Some(gen_data(&mut rng, 1, 200)).pack())
        .build();

    let unsigned_tx = TransactionBuilder::default()
        .input(input)
        .output(output_cell_output)
        .output_data(output_cell_data.pack())
        .witness(witness_args.as_bytes().pack())
        .witness(<str as AsRef<[u8]>>::as_ref(additional_witness_arg).pack())
        .cell_dep(CellDep::new_builder().out_point(out_point).build())
        .cell_dep(CellDep::new_builder().out_point(quantum_out_point).build())
        .build();
    let signed_tx = signer.sign_tx(
        &mut rng,
        &unsigned_tx.data(),
        &[(input_cell_output, input_cell_data)],
        0,
    );

    (context, signed_tx.into_view())
}

fn gen_data<R: Rng>(rng: &mut R, min: usize, max: usize) -> Bytes {
    let len = rng.gen_range(min..=max);
    let mut data = vec![0; len];
    rng.fill(&mut data[..]);
    data.into()
}
