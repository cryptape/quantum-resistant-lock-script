use crate::Loader;
use ckb_fips205_utils::signing::*;
use ckb_testtool::{
    ckb_types::{bytes::Bytes, core::TransactionBuilder, packed::*, prelude::*},
    context::Context,
};
use proptest::prelude::*;
use rand::{rngs::StdRng, Rng, SeedableRng};
use rand_core::CryptoRngCore;

const C_NAME: &'static str = "c-sphincs-all-in-one-lock";
const RUST_NAME: &'static str = "sphincs-all-in-one-lock";

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 30, .. ProptestConfig::default()
    })]

    #[test]
    fn test_valid_tx_c_sha2_128f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Sha2128F::new(&mut rng);
        _test_valid_tx(C_NAME, signer, rng);
    }

    #[test]
    fn test_valid_tx_rust_sha2_128f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Sha2128F::new(&mut rng);
        _test_valid_tx(RUST_NAME, signer, rng);
    }

    #[test]
    fn test_valid_tx_c_sha2_128s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Sha2128S::new(&mut rng);
        _test_valid_tx(C_NAME, signer, rng);
    }

    #[test]
    fn test_valid_tx_rust_sha2_128s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Sha2128S::new(&mut rng);
        _test_valid_tx(RUST_NAME, signer, rng);
    }

    #[test]
    fn test_valid_tx_c_sha2_192f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Sha2192F::new(&mut rng);
        _test_valid_tx(C_NAME, signer, rng);
    }

    #[test]
    fn test_valid_tx_rust_sha2_192f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Sha2192F::new(&mut rng);
        _test_valid_tx(RUST_NAME, signer, rng);
    }

    #[test]
    fn test_valid_tx_c_sha2_192s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Sha2192S::new(&mut rng);
        _test_valid_tx(C_NAME, signer, rng);
    }

    #[test]
    fn test_valid_tx_rust_sha2_192s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Sha2192S::new(&mut rng);
        _test_valid_tx(RUST_NAME, signer, rng);
    }

    #[test]
    fn test_valid_tx_c_shake_128f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Shake128F::new(&mut rng);
        _test_valid_tx(C_NAME, signer, rng);
    }

    #[test]
    fn test_valid_tx_rust_shake_128f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Shake128F::new(&mut rng);
        _test_valid_tx(RUST_NAME, signer, rng);
    }


    #[test]
    fn test_valid_tx_c_shake_128s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Shake128S::new(&mut rng);
        _test_valid_tx(C_NAME, signer, rng);
    }

    #[test]
    fn test_valid_tx_rust_shake_128s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Shake128S::new(&mut rng);
        _test_valid_tx(RUST_NAME, signer, rng);
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 15, .. ProptestConfig::default()
    })]

    #[test]
    fn test_valid_tx_c_sha2_256f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Sha2256F::new(&mut rng);
        _test_valid_tx(C_NAME, signer, rng);
    }

    #[test]
    fn test_valid_tx_rust_sha2_256f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Sha2256F::new(&mut rng);
        _test_valid_tx(RUST_NAME, signer, rng);
    }

    #[test]
    fn test_valid_tx_c_sha2_256s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Sha2256S::new(&mut rng);
        _test_valid_tx(C_NAME, signer, rng);
    }

    #[test]
    fn test_valid_tx_rust_sha2_256s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Sha2256S::new(&mut rng);
        _test_valid_tx(RUST_NAME, signer, rng);
    }

    #[test]
    fn test_valid_tx_c_shake_192f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Shake192F::new(&mut rng);
        _test_valid_tx(C_NAME, signer, rng);
    }

    #[test]
    fn test_valid_tx_rust_shake_192f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Shake192F::new(&mut rng);
        _test_valid_tx(RUST_NAME, signer, rng);
    }


    #[test]
    fn test_valid_tx_c_shake_192s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Shake192S::new(&mut rng);
        _test_valid_tx(C_NAME, signer, rng);
    }

    #[test]
    fn test_valid_tx_rust_shake_192s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Shake192S::new(&mut rng);
        _test_valid_tx(RUST_NAME, signer, rng);
    }

    #[test]
    fn test_valid_tx_c_shake_256f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Shake256F::new(&mut rng);
        _test_valid_tx(C_NAME, signer, rng);
    }

    #[test]
    fn test_valid_tx_rust_shake_256f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Shake256F::new(&mut rng);
        _test_valid_tx(RUST_NAME, signer, rng);
    }


    #[test]
    fn test_valid_tx_c_shake_256s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Shake256S::new(&mut rng);
        _test_valid_tx(C_NAME, signer, rng);
    }

    #[test]
    fn test_valid_tx_rust_shake_256s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Shake256S::new(&mut rng);
        _test_valid_tx(RUST_NAME, signer, rng);
    }
}

fn _test_valid_tx<S: TxSigner, R: Rng + CryptoRngCore>(name: &'static str, signer: S, mut rng: R) {
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary(name);

    let out_point = context.deploy_cell(contract_bin);

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

    let tx = TransactionBuilder::default()
        .input(input)
        .output(output_cell_output)
        .output_data(output_cell_data.pack())
        .witness(witness_args.as_bytes().pack())
        .build();
    let unsigned_tx = context.complete_tx(tx);
    let signed_tx = signer.sign_tx(
        &mut rng,
        &unsigned_tx.data(),
        &[(input_cell_output, input_cell_data)],
        0,
    );

    let cycles = context
        .verify_tx(&signed_tx.into_view(), 200_000_000)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
}

fn gen_data<R: Rng>(rng: &mut R, min: usize, max: usize) -> Bytes {
    let len = rng.gen_range(min..=max);
    let mut data = vec![0; len];
    rng.fill(&mut data[..]);
    data.into()
}
