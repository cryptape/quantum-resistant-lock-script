use crate::{Loader, utils::*};
use ckb_fips205_utils::{Hasher, construct_flag, signing::TxSigner};
use ckb_testtool::{
    ckb_error::Error,
    ckb_types::{
        bytes::Bytes,
        core::{Cycle, TransactionBuilder, TransactionView},
        packed::*,
        prelude::*,
    },
    context::Context,
};
use proptest::{collection::vec, prelude::*};
use rand::{Rng, SeedableRng, rngs::StdRng};
use rand_core::CryptoRngCore;

const C_NAME: &str = "c-sphincs-all-in-one-lock";
const HYBRID_NAME: &str = "hybrid-sphincs-all-in-one-lock";
const RUST_NAME: &str = "sphincs-all-in-one-lock";

proptest! {
    #[test]
    fn test_single_signer_c(
        signer in signer_strategy(),
        seed: u64,
    ) {
        let signers = [signer];
        let rng = StdRng::seed_from_u64(seed);

        let cycles = _run_valid_tx(
            C_NAME,
            &signers,
            1,
            1,
            &[0],
            rng,
        ).expect("pass verification");
        println!("consume cycles: {cycles}");
    }

    #[test]
    fn test_multi_valid_signer_c(
        signers in vec(signer_strategy(), 1..7),
        seed: u64,
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let threshold = rng.gen_range(1..=signers.len());
        println!("Pubkeys: {}, threshold: {}", signers.len(), threshold);
        let selected = gen_selected(
            &mut rng,
            signers.len(),
            threshold,
            0,
        );
        println!("Selected signer indices: {selected:?}");

        let cycles = _run_valid_tx(
            C_NAME,
            &signers,
            threshold,
            0,
            &selected,
            rng,
        ).expect("pass verification");
        println!("consume cycles: {cycles}");
    }

    #[test]
    fn test_multi_valid_signer_first_n_c(
        signers in vec(signer_strategy(), 1..7),
        seed: u64,
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let threshold = rng.gen_range(1..=signers.len());
        let first_n = rng.gen_range(1..=threshold);
        println!("Pubkeys: {}, threshold: {}, require_first_n: {}",
            signers.len(), threshold, first_n);
        let selected = gen_selected(
            &mut rng,
            signers.len(),
            threshold,
            first_n,
        );
        println!("Selected signer indices: {selected:?}");

        let cycles = _run_valid_tx(
            C_NAME,
            &signers,
            threshold,
            first_n,
            &selected,
            rng,
        ).expect("pass verification");
        println!("consume cycles: {cycles}");
    }

    #[test]
    fn test_single_signer_hybrid(
        signer in signer_strategy(),
        seed: u64,
    ) {
        let signers = [signer];
        let rng = StdRng::seed_from_u64(seed);

        let cycles = _run_valid_tx(
            HYBRID_NAME,
            &signers,
            1,
            1,
            &[0],
            rng,
        ).expect("pass verification");
        println!("consume cycles: {cycles}");
    }

    #[test]
    fn test_multi_valid_signer_hybrid(
        signers in vec(signer_strategy(), 1..7),
        seed: u64,
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let threshold = rng.gen_range(1..=signers.len());
        println!("Pubkeys: {}, threshold: {}", signers.len(), threshold);
        let selected = gen_selected(
            &mut rng,
            signers.len(),
            threshold,
            0,
        );
        println!("Selected signer indices: {selected:?}");

        let cycles = _run_valid_tx(
            HYBRID_NAME,
            &signers,
            threshold,
            0,
            &selected,
            rng,
        ).expect("pass verification");
        println!("consume cycles: {cycles}");
    }

    #[test]
    fn test_multi_valid_signer_first_n_hybrid(
        signers in vec(signer_strategy(), 1..7),
        seed: u64,
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let threshold = rng.gen_range(1..=signers.len());
        let first_n = rng.gen_range(1..=threshold);
        println!("Pubkeys: {}, threshold: {}, require_first_n: {}",
            signers.len(), threshold, first_n);
        let selected = gen_selected(
            &mut rng,
            signers.len(),
            threshold,
            first_n,
        );
        println!("Selected signer indices: {selected:?}");

        let cycles = _run_valid_tx(
            HYBRID_NAME,
            &signers,
            threshold,
            first_n,
            &selected,
            rng,
        ).expect("pass verification");
        println!("consume cycles: {cycles}");
    }

    #[test]
    fn test_single_signer_rust(
        signer in signer_strategy(),
        seed: u64,
    ) {
        let signers = [signer];
        let rng = StdRng::seed_from_u64(seed);

        let cycles = _run_valid_tx(
            RUST_NAME,
            &signers,
            1,
            1,
            &[0],
            rng,
        ).expect("pass verification");
        println!("consume cycles: {cycles}");
    }

    #[test]
    fn test_multi_valid_signer_rust(
        signers in vec(signer_strategy(), 1..7),
        seed: u64,
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let threshold = rng.gen_range(1..=signers.len());
        println!("Pubkeys: {}, threshold: {}", signers.len(), threshold);
        let selected = gen_selected(
            &mut rng,
            signers.len(),
            threshold,
            0,
        );
        println!("Selected signer indices: {selected:?}");

        let cycles = _run_valid_tx(
            RUST_NAME,
            &signers,
            threshold,
            0,
            &selected,
            rng,
        ).expect("pass verification");
        println!("consume cycles: {cycles}");
    }

    #[test]
    fn test_multi_valid_signer_first_n_rust(
        signers in vec(signer_strategy(), 1..7),
        seed: u64,
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let threshold = rng.gen_range(1..=signers.len());
        let first_n = rng.gen_range(1..=threshold);
        println!("Pubkeys: {}, threshold: {}, require_first_n: {}",
            signers.len(), threshold, first_n);
        let selected = gen_selected(
            &mut rng,
            signers.len(),
            threshold,
            first_n,
        );
        println!("Selected signer indices: {selected:?}");

        let cycles = _run_valid_tx(
            RUST_NAME,
            &signers,
            threshold,
            first_n,
            &selected,
            rng,
        ).expect("pass verification");
        println!("consume cycles: {cycles}");
    }
}

proptest! {
    #[test]
    fn test_multi_fewer_signer_c(
        signers in vec(signer_strategy(), 1..7),
        seed: u64,
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let threshold = rng.gen_range(1..=signers.len());
        let first_n = rng.gen_range(1..=threshold);
        println!("Pubkeys: {}, threshold: {}, require_first_n: {}",
            signers.len(), threshold, first_n);
        let selected = gen_selected(
            &mut rng,
            signers.len(),
            threshold - 1,
            0,
        );
        println!("Selected signer indices: {selected:?}");

        let e = _run_valid_tx(
            C_NAME,
            &signers,
            threshold,
            first_n,
            &selected,
            rng,
        ).unwrap_err();
        assert!(!format!("{e}").contains("ExceededMaximumCycles"));
    }

    #[test]
    fn test_multi_fewer_signer_hybrid(
        signers in vec(signer_strategy(), 1..7),
        seed: u64,
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let threshold = rng.gen_range(1..=signers.len());
        let first_n = rng.gen_range(1..=threshold);
        println!("Pubkeys: {}, threshold: {}, require_first_n: {}",
            signers.len(), threshold, first_n);
        let selected = gen_selected(
            &mut rng,
            signers.len(),
            threshold - 1,
            0,
        );
        println!("Selected signer indices: {selected:?}");

        let e = _run_valid_tx(
            HYBRID_NAME,
            &signers,
            threshold,
            first_n,
            &selected,
            rng,
        ).unwrap_err();
        assert!(!format!("{e}").contains("ExceededMaximumCycles"));
    }

    #[test]
    fn test_multi_fewer_signer_rust(
        signers in vec(signer_strategy(), 1..7),
        seed: u64,
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let threshold = rng.gen_range(1..=signers.len());
        let first_n = rng.gen_range(1..=threshold);
        println!("Pubkeys: {}, threshold: {}, require_first_n: {}",
            signers.len(), threshold, first_n);
        let selected = gen_selected(
            &mut rng,
            signers.len(),
            threshold - 1,
            0,
        );
        println!("Selected signer indices: {selected:?}");

        let e = _run_valid_tx(
            RUST_NAME,
            &signers,
            threshold,
            first_n,
            &selected,
            rng,
        ).unwrap_err();
        assert!(!format!("{e}").contains("ExceededMaximumCycles"));
    }

    #[test]
    fn test_multi_fewer_first_n_signer_c(
        signers in vec(signer_strategy(), 2..7),
        seed: u64,
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let threshold = rng.gen_range(1..signers.len());
        let first_n = rng.gen_range(1..=threshold);
        println!("Pubkeys: {}, threshold: {}, require_first_n: {}",
            signers.len(), threshold, first_n);
        let selected = gen_selected_full(
            &mut rng,
            signers.len(),
            threshold,
            first_n,
            threshold,
            first_n - 1,
        );
        println!("Selected signer indices: {selected:?}");

        let e = _run_valid_tx(
            C_NAME,
            &signers,
            threshold,
            first_n,
            &selected,
            rng,
        ).unwrap_err();
        assert!(!format!("{e}").contains("ExceededMaximumCycles"));
    }

    #[test]
    fn test_multi_fewer_first_n_signer_hybrid(
        signers in vec(signer_strategy(), 2..7),
        seed: u64,
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let threshold = rng.gen_range(1..signers.len());
        let first_n = rng.gen_range(1..=threshold);
        println!("Pubkeys: {}, threshold: {}, require_first_n: {}",
            signers.len(), threshold, first_n);
        let selected = gen_selected_full(
            &mut rng,
            signers.len(),
            threshold,
            first_n,
            threshold,
            first_n - 1,
        );
        println!("Selected signer indices: {selected:?}");

        let e = _run_valid_tx(
            HYBRID_NAME,
            &signers,
            threshold,
            first_n,
            &selected,
            rng,
        ).unwrap_err();
        assert!(!format!("{e}").contains("ExceededMaximumCycles"));
    }

    #[test]
    fn test_multi_fewer_first_n_signer_rust(
        signers in vec(signer_strategy(), 2..7),
        seed: u64,
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let threshold = rng.gen_range(1..signers.len());
        let first_n = rng.gen_range(1..=threshold);
        println!("Pubkeys: {}, threshold: {}, require_first_n: {}",
            signers.len(), threshold, first_n);
        let selected = gen_selected_full(
            &mut rng,
            signers.len(),
            threshold,
            first_n,
            threshold,
            first_n - 1,
        );
        println!("Selected signer indices: {selected:?}");

        let e = _run_valid_tx(
            RUST_NAME,
            &signers,
            threshold,
            first_n,
            &selected,
            rng,
        ).unwrap_err();
        assert!(!format!("{e}").contains("ExceededMaximumCycles"));
    }
}

fn _run_valid_tx<R: Rng + CryptoRngCore>(
    name: &'static str,
    signers: &[Signer],
    threshold: usize,
    require_first_n: usize,
    signed_indices: &[usize],
    mut rng: R,
) -> Result<Cycle, Error> {
    let conf = build_multisig_configuration(signers, threshold, require_first_n);
    let (context, unsigned_tx, inputs, first_script_group_index) =
        _build_unsigned_tx(name, conf, &mut rng);
    let signed_tx = _sign_multisig_tx(
        &unsigned_tx,
        &inputs,
        first_script_group_index,
        signers,
        signed_indices,
        &mut rng,
    );

    if let Some(path) = std::env::var_os("DUMP_TXS_PATH") {
        if let Ok(s) = std::env::var("DUMP_PROBABILITY") {
            let prob = u16::from_str_radix(&s, 10).expect("parse dump probability");
            if prob > 256 {
                panic!("DUMP_PROBABILITY can only range from 0 to 256!");
            }
            let val = signed_tx.hash().nth0().as_slice()[0] as u16;
            if val < prob {
                let directory = std::path::Path::new(&path);
                std::fs::create_dir_all(directory).expect("mkdir -p");

                let path = directory.join(format!("0x{:x}.json", signed_tx.hash()));
                let mock_tx = context.dump_tx(&signed_tx).expect("dump failed tx");
                let json = serde_json::to_string_pretty(&mock_tx).expect("json");
                std::fs::write(path, json).expect("write");
            }
        }
    }

    context.verify_tx(&signed_tx, 1_000_000_000)
}

fn _sign_multisig_tx<R: Rng + CryptoRngCore>(
    tx: &TransactionView,
    inputs: &[(CellOutput, Bytes)],
    first_script_group_index: usize,
    signers: &[Signer],
    sign_indices: &[usize],
    rng: &mut R,
) -> TransactionView {
    let mut lock: Vec<u8> = vec![];

    for (i, signer) in signers.iter().enumerate() {
        if sign_indices.contains(&i) {
            // Sign the transaction, then extract signature
            let single_signed_tx =
                signer.sign_tx(rng, &tx.data(), inputs, first_script_group_index);
            let first_witness = single_signed_tx
                .witnesses()
                .get(first_script_group_index)
                .unwrap();
            let witness_args =
                WitnessArgs::from_slice(&first_witness.raw_data()).expect("parse witness args");
            let single_lock: Bytes = witness_args.lock().to_opt().unwrap().unpack();
            lock.extend(&single_lock[4..]);
        } else {
            // Only append param Id & public key
            lock.push(construct_flag(signer.param_id(), false));
            lock.extend(&signer.public_key_bytes());
        }
    }

    // Append lock to current tx
    let mut witnesses: Vec<_> = tx.witnesses().into_iter().collect();
    let witness_args = WitnessArgs::from_slice(&witnesses[first_script_group_index].raw_data())
        .expect("parse witness args");
    let mut current_lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
    current_lock.extend(&lock);
    let witness_args = witness_args
        .as_builder()
        .lock(Some(Bytes::from(current_lock)).pack())
        .build();
    witnesses[first_script_group_index] = witness_args.as_bytes().pack();

    tx.as_advanced_builder().set_witnesses(witnesses).build()
}

fn _build_unsigned_tx<R: Rng + CryptoRngCore>(
    name: &'static str,
    multisig_configuration: Bytes,
    mut rng: R,
) -> (Context, TransactionView, Vec<(CellOutput, Bytes)>, usize) {
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary(name);

    let out_point = context.deploy_cell(contract_bin);

    let mut hasher = Hasher::script_args_hasher();
    hasher.update(&multisig_configuration);
    let script_args = hasher.hash().to_vec().into();

    let lock_script = context
        .build_script(&out_point, script_args)
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

    let output_cell_data = gen_data(&mut rng, 1, 500);
    let output_cell_output = CellOutput::new_builder()
        .capacity((1999u64 * 100000000u64).pack())
        .lock(lock_script.clone())
        .build();

    let witness_args = WitnessArgs::new_builder()
        .lock(Some(multisig_configuration.slice(0..4)).pack())
        .input_type(Some(gen_data(&mut rng, 1, 50)).pack())
        .output_type(Some(gen_data(&mut rng, 1, 50)).pack())
        .build();

    let tx = TransactionBuilder::default()
        .input(input)
        .output(output_cell_output)
        .output_data(output_cell_data.pack())
        .witness(witness_args.as_bytes().pack())
        .build();
    let unsigned_tx = context.complete_tx(tx);

    (
        context,
        unsigned_tx,
        vec![(input_cell_output, input_cell_data)],
        0,
    )
}

fn gen_data<R: Rng>(rng: &mut R, min: usize, max: usize) -> Bytes {
    let len = rng.gen_range(min..=max);
    let mut data = vec![0; len];
    rng.fill(&mut data[..]);
    data.into()
}

fn gen_selected<R: Rng>(
    rng: &mut R,
    pubkeys: usize,
    threshold: usize,
    first_n: usize,
) -> Vec<usize> {
    gen_selected_full(rng, pubkeys, threshold, first_n, threshold, first_n)
}

fn gen_selected_full<R: Rng>(
    rng: &mut R,
    pubkeys: usize,
    threshold: usize,
    first_n: usize,
    pick_threshold: usize,
    pick_first_n: usize,
) -> Vec<usize> {
    assert!(threshold <= pubkeys);
    assert!(first_n <= pubkeys);
    assert!(first_n <= threshold);
    assert!(pick_first_n <= pick_threshold);
    assert!(pick_first_n <= first_n);
    assert!(pick_threshold <= threshold);
    assert!(pubkeys - first_n >= pick_threshold - pick_first_n);

    let mut res = vec![];
    if pick_first_n > 0 {
        res.extend(rand::seq::index::sample(rng, first_n, pick_first_n));
    }
    if pick_threshold > pick_first_n {
        let additional =
            rand::seq::index::sample(rng, pubkeys - first_n, pick_threshold - pick_first_n);
        for i in additional {
            res.push(i + first_n);
        }
    }
    res
}
